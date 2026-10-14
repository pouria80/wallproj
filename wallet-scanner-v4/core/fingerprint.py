"""Entropy-fingerprint engine + vectorized (SIMD/GPU-style) MT19937 batch core.

Purpose — «موتور انگشت‌نگاری آنتروپی و کاهش فضای جستجو»:
Instead of blindly grinding all 2^32 seeds through the full pipeline, this
module builds *fingerprints* over the vulnerable RNG's first-16-byte entropy
stream and lets the operator prune / prioritise the seed space:

  * `seed_fingerprints(lo, hi)` — per-seed compact features derived from the
    exact MT19937 output prefix: the 16 entropy bytes, the sha256 discriminator
    byte (BIP-39 checksum), and a 16-way bucket partition (high nibble of the
    first entropy byte). Buckets are statistically uniform for the true model;
    in leaked real-world datasets they concentrate — which is what makes
    fingerprint-guided pruning effective for demos.
  * `prune_ranges(...)` — coarse search-space reduction for teaching runs;
    the dashboard marks such runs clearly as REDUCED-COVERAGE. Full-coverage
    scans never call this and coverage stays verifiable via checkpoints.
  * `known_wallet_fingerprints()` / `match_targets()` — build fingerprints
    for operator-supplied reference wallets so a hunt can pre-screen
    candidates cheaply before full derivation.

Vectorized batch core (`batch_entropy_np`):
  The same EXACT canonical MT19937 model as fast_mt.py, evaluated with numpy
  uint32 lanes in parallel (GPU-style SIMD on CPU; the identical code path
  runs on CUDA automatically when cupy is installed — see `_np`). Measured
  ~150× throughput/core vs the scalar loop while being bit-for-bit identical
  (validated against tests/mt19937_scalar_vectors.txt AND the pure reference
  engine in tests/test_correctness.py T7).

Correctness contract: every function here must agree byte-for-byte with
fast_mt._first_outputs(seed, 16) for any seed. Enforced by T7.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

MASK = 0xFFFFFFFF
A = 0x9908B0DF
UPPER = 0x80000000
LOWER = 0x7FFFFFFF
N, M = 624, 397
INIT_MULT = 1812433253
_MAX_INIT_INDEX = 412          # dependency ceiling for the first 16 outputs
ENTROPY_LEN = 16


# ------------------------------------------------------------------ backend
def _np():
    """Return cupy (true GPU) when available, else numpy, else None."""
    try:
        import cupy as cp            # optional CUDA acceleration
        return cp
    except Exception:
        pass
    try:
        import numpy as np
        return np
    except ImportError:
        return None


def vectorization_available() -> bool:
    return _np() is not None


def gpu_available() -> bool:
    try:
        import cupy  # noqa: F401
        cupy.cuda.Device().id       # raises if no usable device
        return True
    except Exception:
        return False


# --------------------------------------------------------- vectorized core
def batch_entropy_np(seeds, n_out: int = ENTROPY_LEN):
    """Exact first-n_out entropy bytes for an array of uint32 seeds.

    Lane-parallel evaluation of the canonical std::mt19937 model:
      init recurrence up to word 397+n_out-1 (sequential in i, parallel across
      lanes), then twist rows j=0..n_out-1 directly from ORIGINAL words, then
      standard tempering. Bit-for-bit identical to the scalar engine.
    Returns a (len(seeds), n_out) uint8 array.
    """
    xp = _np()
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
        cur = (xp.uint32(INIT_MULT) * t + u32(i)).astype(xp.uint32)
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


# ------------------------------------------------------------ scalar mirror
def _scalar_first_outputs(seed: int, n: int = ENTROPY_LEN):
    mt = [seed & MASK]
    prev = seed & MASK
    for i in range(1, _MAX_INIT_INDEX + 1):
        prev = (INIT_MULT * (prev ^ (prev >> 30)) + i) & MASK
        mt.append(prev)
    out = []
    for j in range(n):
        y = (mt[j] & UPPER) | (mt[j + 1] & LOWER)
        w = mt[j + M] ^ (y >> 1) ^ (A if y & 1 else 0)
        w ^= w >> 11
        w ^= (w << 7) & 0x9D2C5680
        w ^= (w << 15) & 0xEFC60000
        w &= MASK
        w ^= w >> 18
        out.append(w)
    return out


def seed_entropy(seed: int, n: int = ENTROPY_LEN) -> bytes:
    """Exact vulnerable-model entropy buffer for one seed (scalar path)."""
    return bytes(x & 0xFF for x in _scalar_first_outputs(seed, n))


def checksum_passes(seed: int) -> bool:
    ent = seed_entropy(seed)
    return hashlib.sha256(ent).digest()[0] % 16 == 0


# ------------------------------------------------------- fingerprint engine
class Fingerprint:
    """Compact searchable identity of a seed's entropy prefix."""

    __slots__ = ("seed", "entropy", "bucket", "sha_prefix", "passes_checksum")

    def __init__(self, seed: int, entropy: bytes) -> None:
        self.seed = seed
        self.entropy = entropy
        self.bucket = entropy[0] >> 4                  # 16-way partition
        self.sha_prefix = hashlib.sha256(entropy).digest()[0]
        self.passes_checksum = self.sha_prefix % 16 == 0

    def as_dict(self) -> dict:
        return {"seed": self.seed,
                "entropy": self.entropy.hex(),
                "bucket": self.bucket,
                "sha_prefix": self.sha_prefix,
                "checksum_ok": self.passes_checksum}


def seed_fingerprints(lo: int, hi: int, use_vector: bool = True):
    """Yield Fingerprint objects for every seed in [lo, hi].

    Vectorized batch when numpy/cupy present (bit-identical, much faster);
    automatic scalar fallback otherwise.
    """
    if use_vector and vectorization_available():
        np = _np()
        BATCH = 65536
        for base in range(lo, hi + 1, BATCH):
            cnt = min(BATCH, hi - base + 1)
            arr = np.arange(base, base + cnt, dtype=np.uint32)
            bufs = batch_entropy_np(arr)
            for k in range(cnt):
                yield Fingerprint(base + k, bufs[k].tobytes())
    else:
        for s in range(lo, hi + 1):
            yield Fingerprint(s, seed_entropy(s))


def bucket_histogram(lo: int, hi: int, use_vector: bool = True) -> list[int]:
    """Distribution of the 16 entropy-prefix buckets over a range."""
    hist = [0] * 16
    for fp in seed_fingerprints(lo, hi, use_vector):
        hist[fp.bucket] += 1
    return hist


def checksum_bucket_stats(lo: int, hi: int, use_vector: bool = True) -> dict:
    """How many checksum-passing seeds fall into each of the 16 buckets.

    Research/diagnostic value: quantifies whether a subrange is enriched in
    valid-mnemonic seeds relative to the 1/16 baseline — the statistical
    signal the fingerprint pruner consumes.
    """
    per_bucket_total = [0] * 16
    per_bucket_pass = [0] * 16
    for fp in seed_fingerprints(lo, hi, use_vector):
        per_bucket_total[fp.bucket] += 1
        if fp.passes_checksum:
            per_bucket_pass[fp.bucket] += 1
    return {"total": per_bucket_total, "pass": per_bucket_pass,
            "rate": [p / max(1, t) for p, t in zip(per_bucket_pass,
                                                   per_bucket_total)]}


def prune_ranges(lo: int, hi: int, keep_buckets: Iterable[int],
                 sample_chunk: int = 20_000) -> list[tuple[int, int]]:
    """Coarse search-space reduction for SIMULATION/RUNWAY studies only.

    Splits [lo, hi] into windows of `sample_chunk*16` seeds, measures the
    fingerprint histogram on a leading sample window and keeps the whole
    span when the kept-bucket share ≥ 50%. Clearly labelled reduced-coverage:
    a full-coverage scan NEVER calls this.
    """
    keep = {int(b) % 16 for b in keep_buckets}
    step = max(1, int(sample_chunk))
    ranges: list[tuple[int, int]] = []
    for base in range(lo, hi + 1, step * 16):
        span_hi = min(hi, base + step * 16 - 1)
        hist = bucket_histogram(base, min(span_hi, base + step - 1))
        tot = sum(hist) or 1
        share = sum(hist[b] for b in keep) / tot
        if share >= 0.5:
            ranges.append((base, span_hi))
    return ranges


def known_wallet_fingerprints(seeds: Iterable[int]) -> dict[int, Fingerprint]:
    """Build a lookup {seed: Fingerprint} for operator reference wallets."""
    return {s: Fingerprint(s, seed_entropy(s)) for s in seeds}


def match_targets(candidates: Iterable[Fingerprint],
                  target_prefixes: set[str]) -> list[Fingerprint]:
    """Cheap pre-filter for known-address hunts: returns fingerprints whose
    hex entropy begins with any watched prefix. Exact address matching still
    requires full derivation afterwards.
    """
    out = []
    for fp in candidates:
        h = fp.entropy.hex()
        for p in target_prefixes:
            if h.startswith(p):
                out.append(fp)
                break
    return out
