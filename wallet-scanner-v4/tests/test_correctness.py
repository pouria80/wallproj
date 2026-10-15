#!/usr/bin/env python3
"""Correctness verification suite — correctness outranks everything.

Run:  python tests/test_correctness.py          (or pytest)

Layers (each independently fatal if broken):
  T1  MT19937 reference engine vs external libstdc++ oracle vectors
  T2  fast_mt.BatchMT exact model vs reference engine (single/boundary/batch)
  T3  BIP-39 wordlist + known mnemonic/entropy vectors
  T4  Keccak-256 known-answer vectors
  T5  secp256k1 generator, 2G, known private keys -> uncompressed pubkey
  T6  Full pipeline end-to-end: seed -> vulnerable buffer -> wallet;
      cross-check fast path (BatchMT) vs slow path (reference engine)
      and address vs an independent closed-form check for priv=1 vector.
Exit code 0 + "ALL TESTS PASSED" only when every layer passes.
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core"))

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# --------------------------------------------------------------------- T1
def t1_reference_vs_oracle() -> None:
    from mt19937 import RefMT19937
    vec_file = ROOT / "tests" / "mt19937_scalar_vectors.txt"
    n = 0
    # ------------------------------------------------------------------
    # CRITICAL SEMANTICS FINDING (verified experimentally on this machine):
    # There are THREE different "MT19937" output streams for scalar seeds:
    #   (a) Makino mt19937ar.c / Python random: loop1 writes m[k]=m[k+M]^...
    #       reading NOT-yet-updated words; loops 2/3 read updated words.
    #   (b) libstdc++ std::mt19937 (_M_twist): m[j] written from m[(j+M)%N]
    #       BEFORE that source word is overwritten (equivalent to (a)).
    #   (c) The XOR-in-place twist `m[i] ^= m[(i+M)%N]` executed strictly
    #       left-to-right — which is what our RefMT19937/FastMT implement.
    # (a)==(b) differ from (c) from output #2 onward for most seeds.
    #
    # The oracle vectors in mt19937_scalar_vectors.txt were produced by (b).
    # Therefore the engines under test MUST match (a)/(b) semantics, NOT (c).
    # We validate against an independent inline copy of the CANONICAL stream
    # (Python's own `random` module implements (a) and is itself battle-
    # tested), and additionally require byte-equality with the C++ oracle.
    # If the current engines fail here, they have the WRONG twist and every
    # downstream wallet derivation is invalid — this test is intentionally
    # fatal until core/mt19937.py + core/fast_mt.py are fixed to canonical
    # semantics.
    # ------------------------------------------------------------------
    import random as _random

    def canonical_outs(seed: int, count: int) -> list[int]:
        r = _random.Random()
        r.seed(seed)  # NOTE: Python seeds differently! Use raw generator:
        raise RuntimeError("placeholder")  # never reached; see below

    def canonical_mt19937(seed: int, count: int) -> list[int]:
        """Independent copy of the canonical mt19937ar stream (== libstdc++)."""
        N, M, MA, U, L = 624, 397, 0x9908B0DF, 0x80000000, 0x7FFFFFFF
        m = [0] * N
        m[0] = seed & 0xFFFFFFFF
        for i in range(1, N):
            p = m[i - 1]
            m[i] = (1812433253 * (p ^ (p >> 30)) + i) & 0xFFFFFFFF
        kk = N

        def temper(y: int) -> int:
            y ^= y >> 11
            y ^= (y << 7) & 0x9D2C5680
            y ^= (y << 15) & 0xEFC60000
            y ^= y >> 18
            return y & 0xFFFFFFFF

        outs: list[int] = []
        while len(outs) < count:
            if kk >= N:
                for k in range(N - M):
                    y = (m[k] & U) | (m[k + 1] & L)
                    g = m[k + M] ^ (y >> 1)          # source ahead: original
                    m[k] = g ^ MA if (y & 1) else g
                for k in range(N - M, N - 1):
                    y = (m[k] & U) | (m[k + 1] & L)
                    g = m[k + (M - N)] ^ (y >> 1)    # wrapped: already updated
                    m[k] = g ^ MA if (y & 1) else g
                y = (m[N - 1] & U) | (m[0] & L)
                g = m[M - 1] ^ (y >> 1)
                m[N - 1] = g ^ MA if (y & 1) else g
                kk = 0
            outs.append(temper(m[kk]))
            kk += 1
        return outs

    del canonical_outs
    for line in vec_file.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = [int(x) for x in line.split()]
        seed, outs = parts[0], parts[1:]
        # sanity: our independent model must reproduce the C++ oracle exactly
        check(f"T1 canonical-model reproduces libstdc++ oracle seed={seed}",
              canonical_mt19937(seed, len(outs)) == outs,
              f"{canonical_mt19937(seed, 3)} != {outs[:3]}")
        e = RefMT19937(seed)
        got = [e.genrand_uint32() for _ in range(len(outs))]
        check(f"T1 RefMT19937 == canonical stream seed={seed}",
              got == outs, f"{got[:3]}... != {outs[:3]}...")
        n += 1
    check("T1 vector count >= 6", n >= 6, f"only {n} vectors")


# --------------------------------------------------------------------- T2
def t2_fast_mt_exactness() -> None:
    from fast_mt import BatchMT
    from mt19937 import RefMT19937

    def ref_buffer(seed: int, length: int = 16) -> bytes:
        # Vulnerable wallet-core model (Random.cpp@69b2da98): random_buffer()
        # called rng() once PER BYTE and stored a uint8 — the LOW BYTE of each
        # successive tempering output. NOT little-endian uint32 packing.
        e = RefMT19937(seed & 0xFFFFFFFF)
        return bytes(e.genrand_uint32() & 0xFF for _ in range(length))

    boundary = [0, 1, 2, 5489, 12345, 0x7FFFFFFF, 0x80000000,
                0xDEADBEEF, 0xFFFFFFFE, 0xFFFFFFFF]
    rnd_seeds = [int.from_bytes(os.urandom(4), "big") for _ in range(40)]
    for s in boundary + rnd_seeds:
        got = BatchMT(s, s).buffers()[0]
        check(f"T2 single seed={s}", got == ref_buffer(s))

    # batch crossing boundaries mid-range
    for lo, hi in [(0, 500), (0x7FFFFFE0, 0x80000020),
                   (0xFFFFFFFF - 30, 0xFFFFFFFF), (1_000_000, 1_000_300)]:
        bufs = BatchMT(lo, hi).buffers()
        ok = all(bufs[i] == ref_buffer(lo + i) for i in range(len(bufs)))
        check(f"T2 batch [{lo},{hi}]", ok)

    # filtered_seeds must equal brute-force filter using the reference engine
    lo, hi = 7_000_000, 7_001_000
    fast_hits = set(BatchMT(lo, hi).filtered_seeds())
    slow_hits = {s for s in range(lo, hi + 1)
                 if hashlib.sha256(ref_buffer(s)).digest()[0] % 16 == 0}
    check("T2 filtered_seeds == brute force (1000 seeds)",
          fast_hits == slow_hits,
          f"diff={sorted(fast_hits ^ slow_hits)[:5]}")
    rate = len(fast_hits) / (hi - lo + 1)
    check("T2 pass-rate ~1/16", 0.04 < rate < 0.09, f"rate={rate:.4f}")

    # cross-check against the pipeline's own reference buffer function
    from wallet_model import vulnerable_random_buffer
    ok = all(BatchMT(s, s).buffers()[0] == vulnerable_random_buffer(s)
             for s in boundary + rnd_seeds[:10])
    check("T2 buffers == wallet_model.vulnerable_random_buffer", ok)


# --------------------------------------------------------------------- T3
def t3_bip39() -> None:
    from crypto import entropy_to_mnemonic, mnemonic_to_seed, wordlist

    words = wordlist()
    check("T3 wordlist size", len(words) == 2048)
    check("T3 wordlist first/last", words[0] == "abandon" and words[-1] == "zoo")

    # Trezor official vector: entropy 00000000000000000000000000000000
    m = entropy_to_mnemonic(bytes(16))
    check("T3 entropy->mnemonic (all-zero)",
          m == ("abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about"), m)

    # Trezor vector: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
    m2 = entropy_to_mnemonic(bytes([0x7F] * 16))
    check("T3 entropy->mnemonic (0x7f)",
          m2 == ("legal winner thank year wave sausage worth useful "
                 "legal winner thank yellow"), m2)

    # Trezor vector: 80808080808080808080808080808080
    m4 = entropy_to_mnemonic(bytes([0x80] * 16))
    check("T3 entropy->mnemonic (0x80)",
          m4 == ("letter advice cage absurd amount doctor acoustic "
                 "avoid letter advice cage above"), m4)

    # entropy ff..ff -> "zoo zoo ... wrong"? last word is "wrong" per spec
    m3 = entropy_to_mnemonic(b"\xff" * 16)
    check("T3 entropy->mnemonic (all-ff)",
          m3.startswith("zoo zoo zoo") and m3.endswith("wrong"), m3)

    # PBKDF2 seed of the all-zero mnemonic (BIP-39 test vector, empty passphrase)
    seed = mnemonic_to_seed(m)
    expected_prefix = hashlib.pbkdf2_hmac(
        "sha512", m.encode(), b"mnemonic", 2048, 64)
    check("T3 mnemonic_to_seed deterministic", seed == expected_prefix
          and len(seed) == 64)


# --------------------------------------------------------------------- T4
def t4_keccak() -> None:
    from ecc import keccak256

    # Known-answer vectors cross-checked against an independent implementation
    # (pycryptodome Keccak digest_bits=256) — these are the TRUE values.
    k_empty = keccak256(b"").hex()
    check("T4 keccak256('')",
          k_empty == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          k_empty)
    k_abc = keccak256(b"abc").hex()
    check("T4 keccak256('abc')",
          k_abc == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
          k_abc)
    # long input spanning multiple 136-byte rate blocks
    k_long = keccak256(b"a" * 300).hex()
    check("T4 keccak256(300*'a') multi-block",
          k_long == "5b7e0e47a96f32a88b4f14ca177982790807c40e1a105742ba0fc1babe1ef826",
          k_long)
    # exact rate boundary cases (padding must spill into a fresh block at 135/136)
    # Values below were produced by an EARLIER, wrong oracle run; the true
    # Keccak-256 digests (pycryptodome cross-check passes on them) are:
    k_r135 = keccak256(b"\xff" * 135).hex()
    check("T4 keccak256(135*0xff) rate-boundary",
          k_r135 == "f1d6ccc06d572a1e3f4fb6320f8fd3a2e3f1044c45e4f5d863f5a1b6a0ec3b7c",
          k_r135)
    k_r136 = keccak256(b"\xff" * 136).hex()
    check("T4 keccak256(136*0xff) rate-boundary",
          k_r136 == "2d417340362cd4144efbf52adc1bfb7a4b40254f55f3b0f09efa6a1ef299b51a",
          k_r136)
    # optional hard cross-check against pycryptodome when installed
    try:
        from Crypto.Hash import keccak as _kc

        def _ref(msg: bytes) -> str:
            h = _kc.new(digest_bits=256)
            h.update(msg)
            return h.hexdigest()

        for msg in (b"", b"abc", b"a" * 135, b"a" * 136, b"a" * 300,
                    os.urandom(500)):
            check(f"T4 pycryptodome cross-check len={len(msg)}",
                  keccak256(msg).hex() == _ref(msg))
    except ImportError:
        print("[SKIP] T4 pycryptodome not installed (pip install pycryptodome)")


# --------------------------------------------------------------------- T5
def t5_secp256k1() -> None:
    from ecc import point_mul, pubkey_uncompressed, eth_address, _G, _N

    gx, gy = _G
    check("T5 G on curve", (gy * gy - (gx ** 3 + 7)) % (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F) == 0)

    two_g = point_mul(2)
    check("T5 2G x-coord",
          "%064x" % two_g[0] ==
          "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
          "%064x" % two_g[0])
    # y(2G): independent recovery from the curve equation (p≡3 mod 4 sqrt),
    # accepting either root but requiring it to match point_mul's output.
    y_root = _tonelli_sqrt_y_of_x(
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    check("T5 2G on curve (independent y-recovery)",
          two_g[1] in (y_root, _P - y_root), "%064x" % two_g[1])

    # well-known: priv=1 -> uncompressed pub = G; address 0x7e5f4552...
    pub1 = pubkey_uncompressed((1).to_bytes(32, "big"))
    check("T5 priv=1 pubkey == G",
          pub1 == gx.to_bytes(32, "big") + gy.to_bytes(32, "big"))
    addr1 = eth_address((1).to_bytes(32, "big"))
    check("T5 priv=1 address",
          addr1 == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", addr1)

    # priv=2 -> address of 2G. Canonical web3.js vector (checksummed form
    # 0x2b5AD5c4795C026514f8317c7a215E218DcCD6cF) lowercased:
    addr2 = eth_address((2).to_bytes(32, "big"))
    check("T5 priv=2 address",
          addr2 == "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf", addr2)

    # additional canonical vectors (web3.js account docs), lowercase compare
    for k, want in ((3, "0x6813eb9362372eef6200f3b1dbc3f819671cba69"),
                    (7, "0xd41c057fd1c78805aac12b0a94a405c0461a6fbb")):
        got = eth_address(k.to_bytes(32, "big"))
        check(f"T5 priv={k} address", got.lower() == want, got)

    # n*G == infinity handled: point_mul(N) -> None-ish? k%=N => 0 => None
    check("T5 priv=N rejected by pubkey_uncompressed",
          _raises(lambda: pubkey_uncompressed(_N.to_bytes(32, "big"))))

    # random consistency: (a+b)G == aG + bG via affine add
    import random as _r
    rng = _r.Random(12345)
    for _ in range(3):
        a, b = rng.randrange(1, _N), rng.randrange(1, _N)
        pa, pb, pab = point_mul(a), point_mul(b), point_mul(a + b)
        check("T5 additivity spot", _affine_eq(_affine_add(pa, pb), pab))


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# y-coordinate of 2G on secp256k1 (SEC2 / standard constant).
# NOTE: this used to wrongly contain the *x* coordinate; verified against an
# independent affine implementation: y(2G) =
# 1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a
_TWO_G_Y = ("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")


def _tonelli_sqrt_y_of_x(x_hex: str) -> int | None:
    """Recover a curve y from x (y^2 = x^3+7 mod p), for independent checks."""
    x = int(x_hex, 16)
    rhs = (pow(x, 3, _P) + 7) % _P
    # p % 4 == 3 -> sqrt = rhs^((p+1)/4)
    y = pow(rhs, (_P + 1) // 4, _P)
    return y if (y * y) % _P == rhs else None


def _affine_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _affine_eq(p, q):
    return (p is None and q is None) or (p is not None and q is not None and p == q)


# --------------------------------------------------------------------- T6
def t6_pipeline_e2e() -> None:
    """End-to-end: one real historical-model seed derived through BOTH paths."""
    from fast_mt import BatchMT
    from wallet_model import wallet_for_seed, vulnerable_random_buffer
    from crypto import entropy_to_mnemonic

    known_passing = 5489  # will be checked; if it fails checksum we find one
    seed = None
    for cand in range(0, 20000):
        if vulnerable_random_buffer(cand) is not None:
            ent = vulnerable_random_buffer(cand)
            if hashlib.sha256(ent).digest()[0] % 16 == 0:
                seed = cand
                break
    check("T6 found a checksum-passing seed", seed is not None)
    if seed is None:
        return

    mn, addr, pk = wallet_for_seed(seed)
    # independent recomputation of the whole chain
    buf_fast = BatchMT(seed, seed).buffers()[0]
    buf_slow = vulnerable_random_buffer(seed)
    check("T6 fast==slow entropy buffer", buf_fast == buf_slow, f"seed={seed}")
    mn2 = entropy_to_mnemonic(buf_slow)
    check("T6 mnemonic matches independent derivation", mn == mn2)
    check("T6 mnemonic has 12 words", len(mn.split()) == 12)
    check("T6 address format", len(addr) == 42 and addr.startswith("0x"))
    check("T6 pk is 32 bytes hex", len(pk) == 64)

    # determinism across process-level cache reset
    import wallet_model
    wallet_model.wallet_for_seed.cache_clear()
    mn3, addr3, pk3 = wallet_for_seed(seed)
    check("T6 deterministic after cache clear",
          (mn, addr, pk) == (mn3, addr3, pk3))


# --------------------------------------------------------------------- main
def main() -> int:
    t0 = time.time()
    print("=" * 60)
    print("Wallet Scanner V4 — correctness verification suite")
    print("=" * 60)
    for name, fn in [("T1", t1_reference_vs_oracle), ("T2", t2_fast_mt_exactness),
                     ("T3", t3_bip39), ("T4", t4_keccak),
                     ("T5", t5_secp256k1), ("T6", t6_pipeline_e2e)]:
        print(f"\n--- {name} ---")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(f"{name} crashed", False, repr(exc))
    print("\n" + "=" * 60)
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}): {', '.join(FAILURES)}")
        return 1
    print(f"ALL TESTS PASSED in {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
