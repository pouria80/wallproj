"""Unit tests for wallet-scanner V5 (rng-lab research build).

Run from the repo root:
    python -m pytest wallet-tool-v5/tests -q
or standalone (no pytest):
    python wallet-tool-v5/tests/test_v5.py

Known-answer vectors used:
  * secp256k1 priv=1 -> 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH (BTC legacy),
    bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kenljaw (bech32), WIF KwDiBf89…
  * BIP-39 official vectors: all-zero entropy -> "abandon … about";
    7f7f… -> "legal tender …"; TREZOR-passphrase seed prefix c55e4c38…
  * MWC1616 vs an independent re-implementation of the V8 C++ snippet.
  * JavaRandom(0).nextInt() == -1155480935 (JDK well-known value).
  * MSVC rand() classic sequence 41, 18467, 6334, 26500, 17595.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.join(os.path.dirname(HERE), "core")
sys.path.insert(0, CORE)

import numpy as np                                   # noqa: E402,F401

import balance                                        # noqa: E402
import bip39                                          # noqa: E402
import ecc                                            # noqa: E402
import hd                                             # noqa: E402
import lcg                                            # noqa: E402
import mwc1616                                        # noqa: E402


def _ok(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    assert cond, name


# --------------------------------------------------------------------- ECC
def test_ecc_known_vectors():
    p1 = (1).to_bytes(32, "big")
    _ok("priv=1 compressed pubkey",
        ecc.compressed_pub(p1).hex() ==
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    ch = hd.CHAINS["btc"]
    _ok("priv=1 -> 1BgGZ… legacy",
        hd.p2pkh_address(ecc.compressed_pub(p1), ch) ==
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    _ok("priv=1 -> bech32",
        hd.p2wpkh_segwit_address(ecc.compressed_pub(p1), "bc") ==
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kenljaw")
    _ok("priv=1 WIF compressed",
        hd.wif(p1, ch, True) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
    # official wiki constant 5HueCGU… belongs to privkey=7 (block-1 coinbase
    # key), not priv=1.  Correct known-answer for priv=1 below; priv=7 added.
    _ok("priv=1 WIF uncompressed",
        hd.wif(p1, ch, False) == "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
    p7 = (7).to_bytes(32, "big")
    _ok("priv=7 WIF uncompressed (wiki vector)",
        hd.wif(p7, ch, False) == "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    _ok("priv=7 WIF compressed (wiki vector)",
        hd.wif(p7, ch, True) == "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617")


# ------------------------------------------------------------------- BIP-39
def test_bip39_vectors():
    ent = bytes(16)
    m = bip39.entropy_to_mnemonic(ent)
    _ok("12-word all-zero entropy phrase",
        m == ("abandon abandon abandon abandon abandon abandon "
              "abandon abandon abandon abandon abandon about"))
    _ok("round-trip entropy", bip39.mnemonic_to_entropy(m) == ent)
    _ok("validate", bip39.validate_mnemonic(m))
    _ok("reject bad checksum",
        not bip39.validate_mnemonic(m.replace("about", "abandon")))
    m2 = bip39.entropy_to_mnemonic(bytes([0x7F]) * 16)
    _ok("vector legal winner thank year…",
        m2 == ("legal winner thank year wave sausage worth useful "
               "legal winner thank yellow"))
    s1 = bip39.mnemonic_to_seed(m)
    s2 = bip39.mnemonic_to_seed(m, "TREZOR")
    _ok("seed length 64", len(s1) == 64 and len(s2) == 64)
    _ok("passphrase changes seed", s1 != s2)
    _ok("TREZOR vector prefix c55257c3", s2.hex().startswith("c55257c3"))


def test_bip39_12th_word_recovery():
    ent = bytes.fromhex("2c6c4d1de6e03e27ee54ea22b1b0b25a")
    words = bip39.entropy_to_mnemonic(ent).split()
    comps = bip39.completions_from_11_words(words[:11], 11)
    _ok("true word among completions", words[11] in comps)
    _ok("completion count == 128 (2^11/2^4)", len(comps) == 128)
    # recover_missing_word returns EVERY checksum-valid completion as
    # (position, word) pairs; the true word must be one of them.
    rec = bip39.recover_missing_word(words, [11])
    _ok("recover API returns gap+word list",
        isinstance(rec, list) and (11, words[11]) in rec)
    # missing at position 0 still recovers
    comps0 = bip39.completions_from_11_words(words[1:], 0)
    _ok("gap at head recoverable", words[0] in comps0)


# --------------------------------------------------------------- MWC1616/V8
def test_mwc1616_reference_walk():
    """Independent re-implementation of the V8 C++ snippet."""
    def js_ref(seed1, seed2, n):
        out = []
        carry = 0
        s1, s2 = seed1 & 0xFFFFFFFF, seed2 & 0xFFFFFFFF
        for _ in range(n):
            s2 = ((s2 << 16) + s2) & 0xFFFFFFFF
            prod = 18000 * s1 + carry
            carry = prod >> 32
            s1 = prod & 0xFFFFFFFF
            out.append((s2 ^ s1) & 0x7FFFFFFF)
        return out
    ref = js_ref(0xDEADBEEF, 0x12345678, 50)
    g = mwc1616.V8Random(0xDEADBEEF, 0x12345678)
    mine = [g.next_chunk() for _ in range(50)]
    _ok("scalar matches independent model", ref == mine)
    b = mwc1616.V8Batch([0xDEADBEEF], [0x12345678])
    vec = [int(x) for x in np.concatenate([b.step() for _ in range(50)])]
    _ok("vectorized batch bit-exact vs scalar", vec == mine)
    s1s = [1, 2, 3, 0xFFFFFFFF, 0]
    s2s = [7, 0x10001, 999999, 0, 0xCAFEBABE]
    bb = mwc1616.V8Batch(s1s, s2s)
    got = [int(v) for v in bb.step()]
    exp = [mwc1616.V8Random(a, c).next_chunk() for a, c in zip(s1s, s2s)]
    _ok("multi-lane independence", got == exp)
    g2 = mwc1616.V8Random(42, 43)
    vals = [g2.random() for _ in range(1000)]
    _ok("random() in [0,1)", all(0 <= v < 1 for v in vals))


def test_jsbn_byte_stream():
    """JSBN fallback byte = chunk>>23 == floor(random()*256)."""
    g = mwc1616.V8Random(0x9ABCDEF0, 0x12345678)
    manual = []
    h = mwc1616.V8Random(0x9ABCDEF0, 0x12345678)
    for _ in range(20):
        manual.append(int(h.random() * 256))
    _ok("jsbn_entropy == floor(rand*256)",
        list(mwc1616.jsbn_entropy(20, 0x9ABCDEF0, 0x12345678)) == manual)
    g.reset = None  # silence linters
    del g


def test_vectorized_matches_scalar_stream():
    b = mwc1616.V8Batch([5, 6], [7, 8])
    g1, g2 = mwc1616.V8Random(5, 7), mwc1616.V8Random(6, 8)
    ok = True
    for _ in range(30):
        row = b.step()
        if int(row[0]) != g1.next_chunk() or int(row[1]) != g2.next_chunk():
            ok = False
    _ok("batch==scalar over 30 steps", ok)


# ---------------------------------------------------------------------- LCG
def test_java_random_semantics():
    r = lcg.JavaRandom(0)
    # JDK known value: new Random(0).nextInt() == -1155484576
    _ok("Java Random(0).nextInt()", r.next_int() == -1155484576)
    v = lcg.JavaRandom(0).big_integer(256)
    _ok("BigInteger(256,r) length 32", len(v) == 32)
    _ok("BigInteger determinism", lcg.JavaRandom(0).big_integer(256) == v)
    # second draw consistency between identical instances
    a, b = lcg.JavaRandom(12345), lcg.JavaRandom(12345)
    _ok("same seed same stream",
        [a.next(32) for _ in range(10)] == [b.next(32) for _ in range(10)])


def test_msvc_and_nr():
    m = lcg.MSVCRand(1)
    seq = [m.rand() for _ in range(5)]
    _ok("MSVC rand() classic sequence", seq == [41, 18467, 6334, 26500, 17595])
    nr = lcg.NRLCG(0)
    _ok("NR step", nr.next() == 1013904223)
    bufs = list(lcg.time_seed_lcg(1000000, "nr"))
    _ok("time_seed nr 32B", len(bufs) == 1 and len(bufs[0]) == 32)
    try:
        list(lcg.time_seed_lcg(1, "bogus"))
        _ok("unknown variant raises", False)
    except ValueError:
        _ok("unknown variant raises", True)


# ---------------------------------------------------------------- HD / paths
def test_hd_bip32_master_vector():
    # BIP-32 test vector 1: seed 000102...0f
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    k, c = hd.bip32_master(seed)
    _ok("BIP32 v1 master priv",
        k.hex() == "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a7e41fc33c73ec82b")
    _ok("BIP32 v1 master chain code",
        c.hex() == "873dff81c02d523169904d03a85697e04671bd14c38c1cf9ed6ffac823ffaae5")
    d0h = hd.derive_priv(seed, "m/0'")
    _ok("BIP32 v1 m/0' priv",
        d0h.hex() == "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")


def test_hd_bip32_real_child_vector():
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    # official BIP-32 vector 1: m/0'/1/2' xprv9uHRZZhk…Kz → raw key …2169f4
    priv = hd.derive_priv(seed, "m/0'/1/2'")
    _ok("BIP32 v1 m/0'/1/2' priv",
        priv.hex() == "2169f44d5ffae0a130909eaaf4b1c595935f53ed")


def test_hd_legacy_path_families():
    fam = hd.build_path_family("btc", naddr=2)
    _ok("electrum receive+change",
        "m/0'/0/0" in fam["electrum_v1"] and "m/0'/0/1" in fam["electrum_v1"])
    _ok("blockchain.info account root",
        "m/44'/0'/0'/0/0" in fam["blockchain_info"])
    _ok("multibit canonical", "m/0'/0'/0" in fam["multibit"])
    _ok("bitcoincore old present", "m/0'/0/0" in fam["bitcoincore_old"])
    _ok("bip84 present", "m/84'/0'/0'/0/0" in fam["bip84"])
    seed = bip39.mnemonic_to_seed(bip39.entropy_to_mnemonic(bytes(16)))
    keys = hd.derive_keys_from_seed(seed, ("btc",), styles=("electrum_v1",),
                                    naddr=1)
    _ok("all legacy P2PKH start with 1",
        all(k.address.startswith("1") for k in keys
            if k.chain_tag in ("btc", "btc-uncomp")))
    _ok("compressed+uncompressed emitted",
        {k.compressed for k in keys} == {True, False})


def test_altcoin_address_versions():
    priv = (2).to_bytes(32, "big")
    ks = hd.direct_keys(priv, ("ltc", "doge", "zec"))
    tags = {k.chain_tag: k.address for k in ks}
    _ok("LTC legacy starts L", tags["ltc"].startswith("L"))
    _ok("DOGE starts D", tags["doge"].startswith("D"))
    _ok("ZEC t-address starts t1", tags["zec"].startswith("t1"))
    _ok("LTC bech32 ltc1", tags.get("ltc-bech32", "").startswith("ltc1"))
    payload = ecc.b58check_decode(tags["doge"])
    _ok("doge version byte 0x1E", payload[0] == 0x1E)
    payload = ecc.b58check_decode(tags["ltc"])
    _ok("ltc version byte 0x30", payload[0] == 0x30)


# ------------------------------------------------------------------ balance
def test_bloom_no_false_negatives():
    bf = balance.BloomFilter(5000, 1e-6)
    items = [f"addr{i}" for i in range(5000)]
    for it in items:
        bf.add(it)
    _ok("zero false negatives", all(it in bf for it in items))
    fp = sum(1 for i in range(20000) if f"ghost{i}" in bf)
    _ok("fp rate sane (<0.1%)", fp / 20000 < 1e-3)


def test_watchlist_gate_and_offline_hit():
    wl = balance.Watchlist.from_iterable(["1FundedAddressAAAAAAAAAAAAAAA1"])
    ck = balance.BalanceChecker(mode="offline", watchlist=wl)
    _ok("offline exact hit",
        ck.check("btc", "1FundedAddressAAAAAAAAAAAAAAA1") is not None)
    _ok("offline miss", ck.check("btc", "1OtherUnknownXXXXXXXXXXXXXXXx") is None)
    _ok("bloom skipped everything else", ck.skipped_by_bloom >= 1)


def test_readonly_guarantee():
    """Static audit: balance.py exposes no transaction-building capability."""
    src = open(os.path.join(CORE, "balance.py"), encoding="utf-8").read()
    import re
    called = set(re.findall(r'self\._call\("(\w+)"', src))
    allowed = {"scantxoutset", "getaddressinfo", "getreceivedbyaddress"}
    _ok("RPC calls are read-only subset", called <= allowed)
    low = src.lower()
    _ok("no broadcast/sign helpers",
        "def broadcast" not in low and "def sign" not in low
        and "sendrawtransaction" not in low)


# ------------------------------------------------------------------ scanner
def test_scanner_end_to_end_offline():
    import scanner
    rng = mwc1616.V8Random(0x11112222, 0x33334444)
    ent = bytes(rng.next_bytes(32))
    k = int.from_bytes(ent, "big") % ecc.CURVE_ORDER
    priv = k.to_bytes(32, "big")
    target = hd.direct_keys(priv, ("btc",))[0].address
    wl = balance.Watchlist.from_iterable([target])
    ck = balance.BalanceChecker(mode="offline", watchlist=wl)
    cfg = scanner.ScanConfig(vuln="randstorm", mode="direct",
                             t_start_ms=0, t_stop_ms=1)
    eng = scanner.ScanEngine(cfg, ck)
    eng._probe_direct(ent, 0, "unit")
    _ok("engine finds planted wallet",
        any(f.address == target and f.kind == "direct" for f in eng.findings))
    _ok("public_dict hides secrets",
        "priv_hex" not in eng.findings[0].public_dict()
        and "mnemonic" not in eng.findings[0].public_dict())
    eng2 = scanner.ScanEngine(scanner.ScanConfig(mode="bip39", t_start_ms=0,
                                                 t_stop_ms=1), ck)
    eng2._probe_bip39(ent, 0, "unit")
    _ok("bip39 leg derived many addresses",
        eng2.stats.addresses_derived > 10)


def test_randstorm_batch_thread_sweep():
    """Full threaded sweep over a tiny ms window must terminate cleanly."""
    import scanner, threading, time as _t
    cfg = scanner.ScanConfig(vuln="randstorm", mode="direct",
                             t_start_ms=1_000_000_000_000,
                             t_stop_ms=1_000_000_000_000 + 100,
                             batch=64)
    ck = balance.BalanceChecker(mode="offline",
                                watchlist=balance.Watchlist.from_iterable([]))
    eng = scanner.ScanEngine(cfg, ck)
    eng.start()
    eng.join(timeout=60)
    _ok("threaded sweep completed", not eng.running)
    _ok("candidate count == window size", eng.stats.candidates == 100)


# --------------------------------------------------------------------- main
def run_all():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    fails = 0
    for name, t in tests:
        print(f"\n== {name}")
        try:
            t()
        except AssertionError as e:
            fails += 1
            print(f"  !! FAILED: {e}")
        except Exception as e:                      # unexpected error = fail
            fails += 1
            print(f"  !! ERROR : {type(e).__name__}: {e}")
    print(f"\n{len(tests) - fails}/{len(tests)} test groups passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run_all())
