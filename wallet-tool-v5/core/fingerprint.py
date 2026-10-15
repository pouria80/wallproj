"""RNG fingerprinting & search-space reduction (V5.1).

«انگشت‌نگاری RNG — شناسایی خودکار نوع مولد و کاهش فضای جستجو»

Two jobs:

  1. CLASSIFY  — given a short observed byte stream (an entropy buffer, the
     first bytes of a dump, or a known weak-wallet artifact), decide which
     PRNG family most plausibly produced it and return a ranked list of
     hypotheses with confidence scores:

         randstorm/mwc1616   V8 Math.random()  (JSBN top-byte pattern)
         lcg/java            java.util.Random  (48-bit LCG)
         lcg/msvc_mod        MSVC rand()%256   (only values < 128 possible!)
         lcg/msvc_top        MSVC packed rand() words
         lcg/nr              Numerical-Recipes LCG bytes
         mt19937/std         std::mt19937 low-byte-per-byte (Trust Wallet)

     The tests are cheap statistical signatures, NOT proofs; the engine uses
     them to pick the sweep order and to shrink the time window.

  2. REDUCE    — once a family is chosen, prune the candidate space safely:
         * time-window narrowing from a known creation timestamp ± tolerance
         * BIP-39 checksum pre-filter (drops only candidates that could never
           have produced a valid phrase → coverage-preserving)
         * bucket/parity fingerprints for optional REDUCED-COVERAGE sweeps
           (loudly labelled "REDUCED" — false negatives become possible)

  SAFETY NOTE (load-bearing): any filter that DROPS candidates based on
  heuristics (bucket pruning) reduces coverage below 100%.  Checksum-based
  pruning is exact and always safe.  `prune_plan()` reports which kind each
  step is so callers can label runs honestly in UI/logs.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

# family labels understood by the scanner's ScanConfig.vuln mapping
FAMILIES = ("randstorm/mwc1616", "lcg/java", "lcg/msvc_mod", "lcg/msvc_top",
            "lcg/nr", "mt19937/std")


# ------------------------------------------------------------------ helpers
def _chi_square_uniform(counts: Iterable[int], k: int) -> float:
    """Pearson chi-square statistic against a uniform distribution over k."""
    c = np.asarray(list(counts), dtype=np.float64)
    n = c.sum()
    if n == 0:
        return 0.0
    exp = n / k
    return float(((c - exp) ** 2 / exp).sum())


def _byte_entropy(buf: bytes) -> float:
    """Shannon entropy in bits/byte (max 8.0)."""
    hist = np.bincount(np.frombuffer(buf, dtype=np.uint8), minlength=256)
    p = hist[hist > 0] / len(buf)
    return float(-(p * np.log2(p)).sum())


# ------------------------------------------------------------- signatures
def score_msvc_mod(buf: bytes) -> float:
    """MSVC `rand()%256` can NEVER emit bytes >= 128 (rand() ≤ 32767).

    A buffer with zero high-half bytes after n samples is overwhelming
    evidence for this generator (p ≈ 2^-n under any other model).
    """
    if not buf:
        return 0.0
    hi = sum(1 for b in buf if b >= 128)
    return 1.0 if hi == 0 else 0.0


def score_mwc1616(buf: bytes) -> float:
    """JSBN draws one byte per chunk as floor(rand*256) = chunk>>23.

    V8 chunks are 31-bit; the resulting byte stream has no structural bias,
    but consecutive bytes share the MWC recurrence — measurable via the lag-1
    correlation of successive top-bytes being far from what independent
    uniform bytes give.  Weak signal; used mostly as a tie-breaker.
    """
    if len(buf) < 8:
        return 0.0
    x = np.frombuffer(buf, dtype=np.uint8).astype(np.float64)
    x -= x.mean()
    d = float((x * x).sum())
    if d == 0:
        return 0.0
    r = abs(float((x[:-1] * x[1:]).sum()) / d)
    # |r| near 0 => consistent with the model; map to [0,1] confidence
    return max(0.0, 1.0 - min(r * 3.0, 1.0)) * 0.5


def score_mt19937(buf: bytes) -> float:
    """Trust-Wallet path: one rng() call PER BYTE, low byte of tempered out.

    Signature: low bit of MT output is perfectly balanced AND the byte values
    pass a per-nibble uniformity test slightly better than chance would
    demand… In practice we use the NEGATIVE test: streams that fail basic
    uniformity get zero MT confidence.  Positive identification needs seed
    reconstruction (see `find_mt_seed`), which is exact.
    """
    if len(buf) < 8:
        return 0.0
    arr = np.frombuffer(buf, dtype=np.uint8)
    nib = np.bincount(np.concatenate([arr >> 4, arr & 0xF]), minlength=16)
    chi = _chi_square_uniform(nib, 16)
    crit16 = 32.8      # chi2 0.95 critical value, df=15
    return 0.6 if chi < crit16 else 0.05


def score_java_lcg(buf: bytes) -> float:
    """Java BigInteger(256, Random) / next_bytes take TOP bytes of 32-bit
    outputs — statistically indistinguishable without seed recovery.
    Returns a flat prior; `find_java_state()` upgrades it to certainty.
    """
    return 0.2 if len(buf) >= 8 else 0.0


def score_nr_lcg(buf: bytes) -> float:
    """Numerical-Recipes LCG takes the MIDDLE byte of seed*mult+add each
    step; that byte cycles with a strong low-bit period signature — the
    stream is NEVER perfectly parity-balanced over short windows (the
    middle byte's bit0 has period ~4).  Streams with exact parity balance
    are therefore evidence AGAINST nr."""
    if len(buf) < 8:
        return 0.0
    evens = sum(1 for b in buf if b % 2 == 0)
    n = len(buf)
    # z-score of parity split under binomial(n, .5)
    import math as _m
    sd = _m.sqrt(n * 0.25)
    z = abs(evens - n / 2) / sd if sd else 0.0
    # unbalanced parity => consistent with nr middle-byte cycle
    return 0.25 + min(z / 6.0, 0.25) if z > 1.0 else 0.2


def score_msvc_top(buf: bytes) -> float:
    """MSVC two-rand packing: every 16-bit word has its top bit ZERO
    (w = (rand<<15)|rand ⇒ bit15 = rand&1 … actually w < 2^30); more usable:
    bytes at even positions come from (rand>>?) patterns — weak. Keep prior.
    """
    return 0.2 if len(buf) >= 8 else 0.0


_SCORERS = {
    "lcg/msvc_mod": score_msvc_mod,
    "randstorm/mwc1616": score_mwc1616,
    "mt19937/std": score_mt19937,
    "lcg/java": score_java_lcg,
    "lcg/nr": score_nr_lcg,
    "lcg/msvc_top": score_msvc_top,
}


@dataclass
class Hypothesis:
    family: str
    score: float
    detail: str = ""

    def as_dict(self) -> dict:
        return {"family": self.family, "score": round(self.score, 4),
                "detail": self.detail}


@dataclass
class FingerprintReport:
    ranked: List[Hypothesis]
    best: Optional[Hypothesis]
    stats: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"best": self.best.as_dict() if self.best else None,
                "ranked": [h.as_dict() for h in self.ranked],
                "stats": self.stats}


def _as_bytes(buf) -> bytes:
    """Accept bytes, bytearray, memoryview or an iterable of ints."""
    if isinstance(buf, (bytes, bytearray)):
        return bytes(buf)
    if isinstance(buf, memoryview):
        return buf.tobytes()
    try:
        return bytes(int(x) if isinstance(x, int) else x[0] for x in buf)
    except Exception:
        raise TypeError(f"cannot interpret {type(buf)} as a byte stream")


def classify_stream(buf) -> FingerprintReport:
    """Rank every supported RNG family against one observed byte buffer."""
    buf = _as_bytes(buf)
    if not buf:
        return FingerprintReport(ranked=[], best=None,
                                 stats={"error": "empty buffer"})
    stats = {
        "length": len(buf),
        "entropy_bits_per_byte": round(_byte_entropy(buf), 3),
        "high_half_count": sum(1 for b in buf if b >= 128),
        "even_count": sum(1 for b in buf if b % 2 == 0),
    }
    # per-family NEGATIVE tests (structural impossibilities): a family whose
    # generator CANNOT produce an observed feature scores 0 regardless of
    # its positive prior.  This is what makes msvc_mod identification exact.
    neg = {
        "lcg/msvc_mod": stats["high_half_count"] > 0,     # never emits ≥128
        "lcg/nr": stats["even_count"] * 2 == len(buf),    # exact parity split
        "mt19937/std": False,
        "randstorm/mwc1616": False,
        "lcg/java": False,
        "lcg/msvc_top": False,
    }
    hyps = []
    for fam, fn in _SCORERS.items():
        s = 0.0 if neg.get(fam) else fn(buf)
        note = ""
        if fam == "lcg/msvc_mod" and s == 1.0:
            note = ("no byte ≥ 128 present — impossible for all other models; "
                    f"p≈2^-{len(buf)} coincidence")
            stats["msvc_mod_proof"] = True
        hyps.append(Hypothesis(fam, s, note))
    # deterministic ranking: score desc, then family-specific priority so
    # that measured-consistency hypotheses (mt/mwc) beat flat LCG priors
    prio = {"lcg/msvc_mod": 0, "mt19937/std": 1, "randstorm/mwc1616": 2,
            "lcg/java": 3, "lcg/nr": 4, "lcg/msvc_top": 5}
    hyps.sort(key=lambda h: (-h.score, prio.get(h.family, 9)))
    return FingerprintReport(ranked=hyps, best=hyps[0], stats=stats)


# ------------------------------------------- exact seed-reconstruction tests
def find_mt_seed(buf: bytes, seed_hi: int = 1 << 32,
                 sample: int = 6) -> Optional[int]:
    """Brute-force check: does ANY uint32 MT seed reproduce `buf`'s prefix?

    Uses the fast vectorized batch engine; scans the full 2^32 space in
    chunks when allowed (`seed_hi`).  Returns the exact seed or None.
    This upgrades mt19937 classification from heuristic to CERTAINTY.
    """
    try:
        import fast_mt
        if not fast_mt.vectorization_available():
            return None
    except Exception:
        return None
    n = min(len(buf), 16)
    target = np.frombuffer(buf[:n], dtype=np.uint8)
    step = 1 << 20
    base = 0
    while base < seed_hi:
        cnt = min(step, seed_hi - base)
        seeds = np.arange(base, base + cnt, dtype=np.uint32)
        bufs = fast_mt.batch_entropy(seeds, n)
        eq = (bufs == target).all(axis=1)
        idx = np.flatnonzero(eq)
        if idx.size:
            return int(seeds[idx[0]])
        base += cnt
    return None


def find_v8_pair(first_two_chunks: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    """Solve the MWC1616 state from two consecutive 31-bit chunks (scalar).

    Not implemented analytically here (carry ambiguity); provided as a hook
    so future work can invert exactly.  Returns None for now — callers fall
    back to time-window sweeping, which is the practical attack anyway.
    """
    return None


# ------------------------------------------------------ search-space reducer
@dataclass
class PruneStep:
    name: str
    keeps: float          # fraction of space retained (1.0 = untouched)
    lossless: bool        # False => run must be labelled REDUCED
    note: str = ""


@dataclass
class PrunePlan:
    steps: List[PruneStep] = field(default_factory=list)

    @property
    def total_keeps(self) -> float:
        k = 1.0
        for s in self.steps:
            k *= s.keeps
        return k

    @property
    def lossless(self) -> bool:
        return all(s.lossless for s in self.steps)

    def as_dict(self) -> dict:
        return {"lossless": self.lossless,
                "keeps_fraction": round(self.total_keeps, 6),
                "steps": [dataclass_to_dict(s) for s in self.steps]}


def dataclass_to_dict(o) -> dict:
    return {"name": o.name, "keeps": o.keeps, "lossless": o.lossless,
            "note": o.note}


def build_prune_plan(vuln: str, mode: str,
                     t_start_ms: int, t_stop_ms: int,
                     known_t_ms: Optional[int] = None,
                     tolerance_s: int = 300,
                     buckets: Optional[Tuple[int, ...]] = None,
                     parity: Optional[int] = None) -> PrunePlan:
    """Compose the reduction steps for one scan configuration.

    * known_t_ms  → window shrinks to ±tolerance_s around the wallet's
      creation timestamp (exact if the true seed-time is inside).
    * mode=bip39  → checksum filter is FREE coverage (lossless): invalid
      phrases could never exist historically.
    * buckets/parity → REDUCED coverage (heuristic pre-filter for quick
      high-value sweeps; labelled loudly).
    """
    plan = PrunePlan()
    span = max(t_stop_ms - t_start_ms, 1)
    if known_t_ms is not None:
        keep = min(1.0, (2 * tolerance_s * 1000) / span)
        plan.steps.append(PruneStep("time-window-narrow", keep, True,
                                    f"±{tolerance_s}s around known seed time"))
    if mode == "bip39":
        plan.steps.append(PruneStep("bip39-checksum", 1.0, True,
                                    "coverage-preserving (invalid phrases "
                                    "could never be real wallets)"))
    if buckets is not None:
        plan.steps.append(PruneStep("entropy-bucket", len(buckets) / 16.0,
                                    False, f"keep buckets {list(buckets)}"))
    if parity is not None:
        plan.steps.append(PruneStep("entropy-parity", 0.5, False,
                                    f"keep parity={parity}"))
    return plan


# ------------------------------------------------------------ fingerprinting
ENTROPY_LEN = 16


def seed_entropy_mt(seed: int, n: int = ENTROPY_LEN) -> bytes:
    """Exact vulnerable-model entropy buffer for one MT seed (scalar truth)."""
    import mt19937
    return mt19937.ref_entropy_buffer(seed)[:n] \
        if n <= 16 else mt19937.ref_entropy_buffer(seed) + b"\x00" * (n - 16)


class EntropyFingerprint:
    """Compact identity of an entropy buffer (bucket/parity/head)."""

    __slots__ = ("bucket", "parity", "head")

    def __init__(self, entropy: bytes):
        self.bucket = entropy[0] >> 4
        self.parity = entropy[0] & 1
        self.head = entropy[:4].hex()

    def as_dict(self) -> dict:
        return {"bucket": self.bucket, "parity": self.parity,
                "head": self.head}

    def __repr__(self) -> str:
        return (f"EntropyFingerprint(bucket={self.bucket:x}, "
                f"parity={self.parity}, head={self.head})")


def fingerprint_of(buf: bytes) -> EntropyFingerprint:
    return EntropyFingerprint(buf)


def bucket_histogram_mt(lo: int, hi: int) -> List[int]:
    """Seeds per entropy[0] high-nibble bucket (vectorized, 16 entries)."""
    hist = [0] * 16
    try:
        import fast_mt
        xp = fast_mt._xp()
    except Exception:
        xp = None
    if xp is None:
        for s in range(lo, hi + 1):
            hist[seed_entropy_mt(s)[0] >> 4] += 1
        return hist
    step = 1 << 17
    base = lo
    while base <= hi:
        cnt = min(step, hi - base + 1)
        arr = np.arange(base, base + cnt, dtype=np.uint32)
        first = fast_mt.batch_entropy(arr)[:, 0]
        hc = np.bincount((first >> 4).astype(np.int64), minlength=16)
        for i in range(16):
            hist[i] += int(hc[i])
        base += step
    return hist


def matches_fingerprint(buf: bytes, buckets: Optional[set] = None,
                        parity: Optional[int] = None) -> bool:
    fp = fingerprint_of(buf)
    if buckets is not None and fp.bucket not in buckets:
        return False
    if parity is not None and fp.parity != parity:
        return False
    return True


# ------------------------------------------- vuln string ↔ family helpers
def family_to_scan_args(family: str) -> Tuple[str, str]:
    """Map a classified family onto (ScanConfig.vuln, extra variant hint)."""
    if family.startswith("randstorm"):
        return "randstorm", ""
    if family.startswith("lcg/"):
        return "lcg", family.split("/", 1)[1]
    if family.startswith("mt19937"):
        return "mt19937", ""
    raise ValueError(f"unknown family {family!r}")
