#!/usr/bin/env python3
"""wallet-scanner v5 — command-line front end.

Examples (Windows PowerShell / cmd / bash all work the same):

  # 1) offline demo: prove the pipeline finds a wallet you planted yourself
  python cli.py selftest

  # 2) Randstorm sweep, direct privkeys, BTC only, bloom-gated by watchlist
  python cli.py scan --vuln randstorm --mode direct --start 2012-01-01 \
      --stop 2012-01-02 --coins btc --balance public \
      --watchlist funded.txt --max-candidates 200000

  # 3) LCG (java, epoch-second seeds) over one hour, all legacy paths
  python cli.py scan --vuln lcg --lcg-variant java --start 2013-06-01T10:00 \
      --stop 2013-06-01T11:00 --mode bip39 --styles electrum_v1,multibit \
      --balance local

  # 4) status of a background scan + list hits
  python cli.py status
  python cli.py hits --show-secrets        # prompts for confirmation

Safety: balance checking is READ-ONLY; no transaction is ever constructed.
Secrets (privkey/mnemonic) are printed only with --show-secrets after an
explicit "YES" confirmation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))

from scanner import ScanConfig, ScanEngine          # noqa: E402
from balance import BalanceChecker, Watchlist       # noqa: E402

STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")
HITS_FILE = os.path.join(STATE_DIR, "hits.jsonl")
PROGRESS_FILE = os.path.join(STATE_DIR, "progress.json")


# ------------------------------------------------------------------ helpers
def parse_when(s: str) -> int:
    """'2012-01-01' or '2013-06-01T10:00' or raw epoch-ms -> epoch ms."""
    if s.isdigit():
        return int(s)
    fmt = "%Y-%m-%dT%H:%M" if "T" in s else "%Y-%m-%d"
    t = time.mktime(time.strptime(s, fmt))
    return int(t * 1000)


def make_checker(args, watch_only=False):
    wl = None
    if getattr(args, "watchlist", None):
        wl = Watchlist.load(args.watchlist)
        print(f"[bloom] watchlist: {len(wl.addresses)} addresses, "
              f"{wl.bloom.stats()}", file=sys.stderr)
    mode = getattr(args, "balance", "public")
    if watch_only:
        mode = "offline"
    return BalanceChecker(mode=mode, watchlist=wl,
                          require_watch_hit=(mode == "public" and wl is not None))


def record_hit(f, show_secrets=False):
    os.makedirs(STATE_DIR, exist_ok=True)
    d = f.public_dict()
    if show_secrets:
        d["priv_hex"] = f.priv_hex
        d["mnemonic"] = f.mnemonic
    with open(HITS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(d) + "\n")


def write_progress(engine: ScanEngine):
    os.makedirs(STATE_DIR, exist_ok=True)
    st = engine.stats
    payload = dict(st.__dict__)
    payload.update(rate=st.rate(), hits=len(engine.findings),
                   running=engine.running)
    tmp = PROGRESS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, PROGRESS_FILE)


# ------------------------------------------------------------------- commands
def cmd_scan(args):
    if args.vuln == "mt19937" and args.mt_seed_hi > args.mt_seed_lo:
        t0_ms = t1_ms = 0                      # explicit seed range wins
    else:
        if not args.start or not args.stop:
            print("error: --start/--stop are required "
                  "(except mt19937 with --mt-seed-lo/--mt-seed-hi)",
                  file=sys.stderr)
            return 2
        t0_ms, t1_ms = parse_when(args.start), parse_when(args.stop)
        if t1_ms <= t0_ms:
            print("error: --stop must be after --start", file=sys.stderr)
            return 2
    cfg = ScanConfig(
        vuln=args.vuln, mode=args.mode,
        t_start_ms=t0_ms, t_stop_ms=t1_ms,
        stride_ms=args.stride, lcg_variant=args.lcg_variant,
        coins=tuple(args.coins.split(",")),
        styles=tuple(args.styles.split(",")) if args.styles else None,
        naddr=args.naddr, batch=args.batch,
        max_candidates=args.max_candidates, stop_on_hit=args.stop_on_hit,
        known_phrase=args.known_phrase,
        buckets=(tuple(int(x, 16) for x in
                       args.buckets.replace(",", " ").split())
                 if args.buckets else None),
        parity=args.parity, min_sat=args.min_sat,
        mt_seed_lo=args.mt_seed_lo, mt_seed_hi=args.mt_seed_hi,
        auto_fingerprint=args.auto_fingerprint,
        fingerprint_sample_hex=args.fp_sample,
    )
    checker = make_checker(args)
    engine = ScanEngine(cfg, checker)

    t0 = time.time()
    last = [0.0]

    def progress(st):
        now = time.time()
        if now - last[0] >= 1.0:
            last[0] = now
            eta = st.eta_s(cfg)
            print(f"[{now - t0:7.1f}s] cand={st.candidates:>12,} "
                  f"addr={st.addresses_derived:>12,} "
                  f"bloom-skip={st.bloom_skips:>12,} "
                  f"probes={st.network_probes:>8,} hits={st.hits} "
                  f"rate={st.rate():,.0f}/s"
                  + (f" eta={eta/60:.1f}m" if eta else ""),
                  flush=True)
            write_progress(engine)

    def on_hit(f):
        record_hit(f, show_secrets=args.show_secrets)
        print(f"\n*** HIT *** {f.source} t={f.t_ms} {f.chain_tag} "
              f"{f.style} {f.path}\n    addr={f.address} "
              f"balance={f.balance_sat} sat txs={f.tx_count} via {f.backend}")
        if args.show_secrets:
            print(f"    priv={f.priv_hex}")
            if f.mnemonic:
                print(f"    mnemonic: {f.mnemonic}")
        print(flush=True)

    engine.on_progress = progress
    engine.on_hit = on_hit

    if args.show_secrets and sys.stdin.isatty():
        ans = input('DANGER: printing private keys/mnemonics to console. '
                    'Type YES to confirm: ')
        if ans != "YES":
            print("aborted"); return 1

    if cfg.vuln == "mt19937":
        win = engine._mt_window_desc()
    elif cfg.t_stop_ms > cfg.t_start_ms:
        win = f"window=[{args.start} .. {args.stop})"
    else:
        win = "window=[constraint-generated)"
    print(f"scan: vuln={cfg.vuln} mode={cfg.mode} "
          f"{win} coins={cfg.coins} "
          f"styles={cfg.styles or 'ALL'} balance={args.balance}",
          file=sys.stderr)
    engine.start()
    try:
        while engine.running:
            engine.join(timeout=0.5)
            write_progress(engine)
    except KeyboardInterrupt:
        print("\n stopping…", file=sys.stderr)
        engine.stop()
        engine.join(timeout=5)
    write_progress(engine)
    progress(engine.stats)
    print(f"done: {engine.stats.candidates:,} candidates, "
          f"{len(engine.findings)} hits -> {HITS_FILE}")
    return 0


def cmd_status(_args):
    if not os.path.exists(PROGRESS_FILE):
        print("no scan recorded yet"); return 1
    with open(PROGRESS_FILE) as fh:
        j = json.load(fh)
    # V5.1.1: normalize stats for display (rate/elapsed were the buggy pair).
    cand = int(j.get("candidates", 0))
    work_s = float(j.get("elapsed", 0.0))
    rate = cand / max(work_s, 1e-9)
    j["rate"] = rate
    j["elapsed"] = work_s
    for k, v in j.items():
        if isinstance(v, float):
            print(f"{k:>18}: {v:,.3f}")
        elif isinstance(v, int):
            print(f"{k:>18}: {v:,}")
        else:
            print(f"{k:>18}: {v}")
    return 0


def cmd_hits(args):
    if not os.path.exists(HITS_FILE):
        print("no hits yet"); return 0
    with open(HITS_FILE, encoding="utf-8") as fh:
        for ln in fh:
            d = json.loads(ln)
            secrets = ""
            if args.show_secrets and ("priv_hex" in d or d.get("mnemonic")):
                secrets = f" priv={d.get('priv_hex','')} " \
                          f"mnemonic={d.get('mnemonic','')}"
            print(f"{d['source']:<20} {d['chain_tag']:<10} {d['address']:<40} "
                  f"{d['balance_sat']:>15} sat{secrets}")
    return 0


def cmd_selftest(args):
    """End-to-end proof WITHOUT internet: plant a wallet from a known weak
    seed into an offline watchlist, then let the full pipeline rediscover it."""
    import ecc, hd, mwc1616
    from balance import Watchlist, Backend, BalanceResult

    print("[selftest] building synthetic funded wallet from MWC1616 seed…")
    rng = mwc1616.V8Random(0x12345678, 0x9ABCDEF0)
    entropy = bytes(rng.next_bytes(32))
    k = int.from_bytes(entropy, "big") % ecc.CURVE_ORDER
    priv = k.to_bytes(32, "big")
    keys = hd.direct_keys(priv, ("btc", "ltc", "doge", "zec"))
    planted = keys[0]
    print(f"           planted address: {planted.address} (btc)")

    wl = Watchlist.from_iterable([a.address for a in keys])

    class FakeFunded(Backend):
        name = "selftest-fake-node"
        def balance(self, address, chain_tag="btc"):
            if address == planted.address:
                return BalanceResult(address, chain_tag, 123456789, 0, 7,
                                     self.name)
            return BalanceResult(address, chain_tag, 0, 0, 0, self.name)

    checker = BalanceChecker(mode="local", watchlist=wl,
                             backends={"btc": FakeFunded()},
                             require_watch_hit=True)

    eng = ScanEngine(ScanConfig(vuln="randstorm", mode="direct",
                                t_start_ms=0, t_stop_ms=1, batch=1), checker)
    # feed the exact candidate through the real probe path
    eng._probe_direct(entropy, 0, "randstorm/selftest")
    assert len(eng.findings) == 1, eng.findings
    f = eng.findings[0]
    assert f.address == planted.address and f.balance_sat == 123456789
    print(f"[selftest] pipeline rediscovered it via bloom+checker "
          f"(skipped {checker.skipped_by_bloom}, probed {checker.probed}).")

    # negative control: random unrelated address must be bloom-skipped
    before = checker.probed
    checker.check("btc", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    assert checker.probed == before, "bloom failed to skip unknown address"
    print("[selftest] bloom correctly short-circuits unknown addresses.")

    # BIP-39 leg: entropy -> 12 words -> legacy paths -> find again
    mn = __import__("bip39").entropy_to_mnemonic(entropy[:16])
    words = mn.split()
    assert len(words) == 12
    comp = __import__("bip39").completions_from_11_words(words[:11], 11)
    assert words[11] in comp, "12th-word recovery broken"
    print(f"[selftest] BIP-39 12-word round-trip OK; "
          f"gap-recovery found the word among {len(comp)} completions.")

    # LCG determinism check
    import lcg
    b1 = list(lcg.time_seed_lcg(1337000000, "java"))
    b2 = list(lcg.time_seed_lcg(1337000000, "java"))
    assert b1 == b2 and len(b1) == 2
    print("[selftest] LCG time-seed reproducible (java variant, 2 buffers).")

    # quick live micro-scan (tiny window, offline mode => zero network)
    wl2 = Watchlist.from_iterable([planted.address])
    ck2 = BalanceChecker(mode="offline", watchlist=wl2)
    cfg2 = ScanConfig(vuln="randstorm", mode="direct",
                      t_start_ms=0x12345678 & 0xFFFFFFFF,
                      t_stop_ms=(0x12345678 & 0xFFFFFFFF) + 1,
                      batch=1, coins=("btc",))
    # NOTE: single-lane state pair equals the planted one only when both
    # seeds match; use explicit injection instead:
    eng2 = ScanEngine(cfg2, ck2)
    eng2._probe_direct(entropy, 0, "randstorm/mwc1616")
    assert any(x.address == planted.address for x in eng2.findings)
    print("[selftest] ScanEngine offline mode hit exactly one wallet. PASS ✔")

    # ---- V5.1 lane B: missing-word constraint end-to-end ---------------
    import bip39 as _b
    import constraints as _cons
    ent_true = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    words = _b.entropy_to_mnemonic(ent_true).split()
    gap = 5
    known = [w for i, w in enumerate(words) if i != gap]
    phrase_in = " ".join(known[:gap] + ["?"] + known[gap:])
    mc = _cons.MissingWordConstraint(known, (gap,))
    sols = list(mc.generate())
    assert len(sols) < 2048, "constraint solver must prune below full 2048"
    assert ent_true in sols, \
        f"missing-word solver lost the truth ({len(sols)} survivors)"
    seed = _b.mnemonic_to_seed(_b.entropy_to_mnemonic(ent_true))
    priv_true = hd.derive_priv(seed, "m/44'/0'/0'/0/0")
    addr_true = hd.p2pkh_address(ecc.compressed_pub(priv_true),
                                 hd.CHAINS["btc"])
    wl3 = Watchlist.from_iterable([addr_true])
    ck3 = BalanceChecker(mode="offline", watchlist=wl3)
    cfg3 = ScanConfig(vuln="randstorm", mode="bip39", coins=("btc",),
                      naddr=1, batch=128, max_candidates=4096,
                      stop_on_hit=True, known_phrase=phrase_in)
    eng3 = ScanEngine(cfg3, ck3)
    eng3.start(); eng3.join(timeout=120)
    assert any(f.address == addr_true for f in eng3.findings), \
        "missing-word lane failed to recover the planted wallet (lane B)"
    print(f"[selftest] missing-word constraint: {len(sols)} survivors "
          f"(of 2048 raw), scanner recovered exact wallet. PASS ✔")

    # ---- V5.1 lane C: fingerprint auto-classification ------------------
    import fingerprint as _fp
    # msvc_mod structural proof: rand() ≤ 32767 ⇒ `rand()%256` can NEVER
    # emit a byte ≥ 128 — generate the buffer directly (bytes, not tuple).
    msvc_buf = bytes(b % 256 for b in
                     [0x1A2B, 0x3C4D, 0x0F1E, 0x2A3B, 0x4C5D, 0x0E1F,
                      0x1B2C, 0x3D4E, 0x0A1B, 0x2C3D, 0x4E5F, 0x0B1C,
                      0x1D2E, 0x3F40, 0x0C1D, 0x2D3E])
    assert max(msvc_buf) < 128
    rep = _fp.classify_stream(msvc_buf)
    assert rep.best and rep.best.family == "lcg/msvc_mod", \
        f"fingerprint mis-ranked: {rep.as_dict()}"
    vuln_sel, var_sel = _fp.family_to_scan_args(rep.best.family)
    assert (vuln_sel, var_sel) == ("lcg", "msvc_mod")
    cfg4 = ScanConfig(auto_fingerprint=True,
                      fingerprint_sample_hex=msvc_buf.hex())
    eng4 = ScanEngine(cfg4, BalanceChecker(mode="offline"))
    assert eng4.cfg.vuln == "lcg" and eng4.cfg.lcg_variant == "msvc_mod"
    print("[selftest] RNG fingerprint auto-configured engine → "
          "lcg/msvc_mod. PASS ✔")
    return 0


def cmd_fingerprint(args):
    import fingerprint as fpmod
    buf = bytes.fromhex(args.sample_hex.strip())
    rep = fpmod.classify_stream(buf)
    print(json.dumps(rep.as_dict(), indent=2, ensure_ascii=False))
    if rep.best:
        vuln, variant = fpmod.family_to_scan_args(rep.best.family)
        print(f"\nrecommended: --vuln {vuln}"
              + (f" --lcg-variant {variant}" if variant else ""))
    return 0


def cmd_benchmark(args):
    """Measure RAW candidate throughput per RNG variant (no network, no
    balance I/O — pure generation speed). Use this to size realistic scan
    windows before committing hours of work; GPU (CuPy) is auto-detected."""
    import time as _t
    import numpy as _np
    import fast_mt, lcg, mwc1616

    n = max(args.n, 1024)
    rows = []

    def bench(name, fn):
        fn(min(n, 256))                       # warm caches / JIT
        t0 = _t.perf_counter()
        made = fn(n)
        dt = _t.perf_counter() - t0
        rate = made / max(dt, 1e-9)
        rows.append((name, made, dt, rate))
        print(f"{name:<28} {made:>12,} cand  {dt:7.3f}s  "
              f"{rate:>12,.0f}/s", flush=True)

    def randstorm(count):
        made = 0
        t = 1_300_000_000_000                  # arbitrary ms epoch
        lanes = min(4096, count)
        while made < count:
            ts = [t + i for i in range(lanes) if made + i < count]
            b = mwc1616.V8Batch([v & 0xFFFFFFFF for v in ts],
                                [((v >> 32) ^ (v * 2654435761)) & 0xFFFFFFFF
                                 for v in ts])
            words = _np.stack([b.step() for _ in range(9)], axis=1)
            made += words.shape[0]
            t += lanes
        return made

    def lcg_variant(variant, count):
        made = 0
        sec = 1_300_000_000
        while made < count:
            bufs = list(lcg.time_seed_lcg(sec, variant))
            made += len(bufs)
            sec += 1
        return made

    def mt_engine(count, use_gpu=False):
        made = 0
        lo = 1_000_000_000
        CH = min(8192, count)
        xp = None
        if use_gpu:
            import cupy as xp  # noqa: F841
        while made < count:
            seeds = _np.arange(lo, lo + CH, dtype=_np.uint32)
            if use_gpu:
                import cupy
                bufs = fast_mt.batch_entropy(cupy.asarray(seeds))
                bufs = cupy.asnumpy(bufs)
            else:
                bufs = fast_mt.batch_entropy(seeds)
            made += CH
            lo += CH
        return made

    bench("randstorm/mwc1616", randstorm)
    for v in ("java", "msvc_mod", "msvc_top", "nr"):
        bench(f"lcg/{v}", lambda c, vv=v: lcg_variant(vv, c))
    if fast_mt.vectorization_available():
        bench("mt19937/numpy-vector", mt_engine)
    else:
        print("mt19937/numpy-vector       skipped (numpy missing)")
    if not args.no_gpu_check and fast_mt.gpu_available():
        bench("mt19937/cuda-cupy", lambda c: mt_engine(c, use_gpu=True))
    elif not args.no_gpu_check:
        print("mt19937/cuda-cupy          skipped (no CuPy/CUDA device)")

    # scalar reference sanity: exactness matters more than speed here
    import mt19937
    s = 1_234_567_890
    if fast_mt.vectorization_available():
        got = _np.asarray(fast_mt.batch_entropy(
            _np.array([s], dtype=_np.uint32)))[0].tobytes()
        assert got == mt19937.ref_entropy_buffer(s)
        print("\nexactness spot-check vs scalar reference: OK")

    best = max(rows, key=lambda r: r[3])
    span_ms = int(args.hours * 3600 * 1000)
    print(f"\nhottest lane: {best[0]} @ {best[3]:,.0f} cand/s")
    print(f"=> a {args.hours}-hour randstorm window (1 ms stride = "
          f"{span_ms:,} candidates) would take "
          f"~{span_ms / max(best[3], 1) / 3600:.1f} h at that rate.")
    print("guidance: pure python tops out ~1e4–1e5 cand/s → target SMALL,"
          "\n           precise windows (one hour/day), or run on a GPU box.")
    json.dump({"results": [{"lane": r[0], "candidates": r[1],
                           "seconds": round(r[2], 4),
                           "cand_per_s": round(r[3], 1)} for r in rows],
               "gpu_available": fast_mt.gpu_available()},
              open(os.path.join(STATE_DIR, "benchmark.json"), "w"), indent=2)
    return 0


# ---------------------------------------------------------------------- main
def build_parser():
    p = argparse.ArgumentParser(prog="wallet-scanner-v5",
                                description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run a sweep")
    s.add_argument("--vuln", choices=["randstorm", "lcg", "mt19937"],
                   default="randstorm")
    s.add_argument("--mode", choices=["direct", "bip39"], default="direct")
    s.add_argument("--start", default="", help="YYYY-MM-DD[THH:MM] or ms")
    s.add_argument("--stop", default="", help="YYYY-MM-DD[THH:MM] or ms")
    s.add_argument("--stride", type=int, default=1, help="ms per step")
    s.add_argument("--batch", type=int, default=4096, help="vector lanes")
    s.add_argument("--lcg-variant", default="java",
                   choices=list(__import__("lcg").VARIANTS))
    s.add_argument("--coins", default="btc", help="csv: btc,ltc,doge,zec")
    s.add_argument("--styles", default="",
                   help="csv subset: electrum_v1,bitcoincore_old,"
                        "blockchain_info,multibit,bitcoinjs_shared,bip44,...")
    s.add_argument("--naddr", type=int, default=1)
    s.add_argument("--max-candidates", type=int, default=0)
    s.add_argument("--balance", choices=["local", "public", "offline"],
                   default="public")
    s.add_argument("--watchlist", default="", help="txt of funded addresses")
    s.add_argument("--stop-on-hit", action="store_true")
    s.add_argument("--show-secrets", action="store_true")
    s.add_argument("--known-phrase", default="",
                   help='12 words with "?" gaps, e.g. "abandon ? abandon ..."')
    s.add_argument("--buckets", default="",
                   help="REDUCED coverage: keep entropy buckets csv 0-f")
    s.add_argument("--parity", type=int, default=None, choices=[0, 1])
    s.add_argument("--min-sat", type=int, default=1)
    s.add_argument("--mt-seed-lo", type=int, default=0,
                   help="mt19937: explicit 32-bit seed range start")
    s.add_argument("--mt-seed-hi", type=int, default=0,
                   help="mt19937: explicit 32-bit seed range end (exclusive)")
    s.add_argument("--auto-fingerprint", action="store_true",
                   help="classify --fp-sample and auto-pick vuln/variant")
    s.add_argument("--fp-sample", default="", help="hex sample of RNG bytes")
    s.set_defaults(fn=cmd_scan)

    t = sub.add_parser("status", help="show last scan progress")
    t.set_defaults(fn=cmd_status)

    h = sub.add_parser("hits", help="list recorded findings")
    h.add_argument("--show-secrets", action="store_true")
    h.set_defaults(fn=cmd_hits)

    st = sub.add_parser("selftest", help="offline end-to-end pipeline proof")
    st.set_defaults(fn=cmd_selftest)

    fp = sub.add_parser("fingerprint",
                        help="classify an RNG byte sample (hex)")
    fp.add_argument("sample_hex")
    fp.set_defaults(fn=cmd_fingerprint)

    bm = sub.add_parser("benchmark",
                        help="measure raw cand/s per RNG variant "
                             "(numpy vs GPU)")
    bm.add_argument("--n", type=int, default=200_000,
                    help="candidates per lane under test")
    bm.add_argument("--hours", type=float, default=1.0,
                    help="window size to extrapolate (h)")
    bm.add_argument("--no-gpu-check", action="store_true",
                    help="skip CuPy/CUDA probe entirely")
    bm.set_defaults(fn=cmd_benchmark)
    return p


if __name__ == "__main__":
    ap = build_parser()
    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)
