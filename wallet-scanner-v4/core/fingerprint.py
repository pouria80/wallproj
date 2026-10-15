"""Entropy-fingerprint utilities — search-space reduction & analysis (V5).

«موتور انگشت‌نگاری آنتروپی و کاهش فضای جستجو»

Every seed in [0, 2^32) produces a deterministic 16-byte entropy buffer under
the vulnerable Trust Wallet MT19937 model. This module exposes:

  * seed_entropy / batch buffers  — DELEGATED to the canonical, oracle-verified
    engines (`fast_mt.batch_entropy` SIMD / `fast_mt._first_outputs` scalar).
    IMPORTANT HISTORY: this file once contained its own vectorized "in-place
    twist" MT model. That model was WRONG (it diverges from libstdc++/mt19937ar
    from output #2 onward for almost every seed). It has been removed; there is
    now exactly ONE source of truth for MT semantics, so no caller can ever
    obtain fingerprint data computed with different math than the scanner uses.

  * Fingerprint objects (bucket = high nibble of entropy[0], parity = bit0,
    checksum verdict) used by the optional REDUCED-COVERAGE pre-filter and by
    the analysis reports (histograms, pass-rate per bucket).

  * prune_ranges() — helper that turns a keep-bucket set into sub-ranges.

SAFETY NOTE (load-bearing): any filter here that DROPS seeds reduces coverage
below 100%. The engine therefore labels such runs "REDUCED" loudly in the UI
and logs. The BIP-39 checksum filter is NOT a reduction: it discards only
seeds whose mnemonic would be invalid (they could never have been real
Trust Wallets), which preserves exact historical coverage.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

ENTROPY_LEN = 16


def _np():
    from fast_mt import _xp
    return _xp()


def vectorization_available() -> bool:
    from fast_mt import vectorization_available as v
    return v()


def gpu_available() -> bool:
    from fast_mt import gpu_available as g
    return g()


# ------------------------------------------------------------------- buffers
def batch_entropy_np(seeds, n_out: int = ENTROPY_LEN):
    """Canonical SIMD entropy buffers (numpy/cupy lanes). Thin delegation to
    `fast_mt.batch_entropy` — kept under the old name for compatibility."""
    from fast_mt import batch_entropy
    return batch_entropy(seeds, n_out)


def _scalar_first_outputs(seed: int, n: int = ENTROPY_LEN):
    from fast_mt import _first_outputs
    return _first_outputs(seed, n)


def seed_entropy(seed: int, n: int = ENTROPY_LEN) -> bytes:
    """Exact vulnerable-model entropy buffer for one seed (scalar path)."""
    return bytes(x & 0xFF for x in _scalar_first_outputs(seed, n))


def checksum_passes(seed: int) -> bool:
    """True iff the seed's 16-byte buffer forms a valid BIP-39 12-word checksum."""
    return hashlib.sha256(seed_entropy(seed)).digest()[0] % 16 == 0


# --------------------------------------------------------------- fingerprints
class Fingerprint:
    """Compact identity of a seed's entropy prefix."""

    __slots__ = ("seed", "bucket", "parity", "head")

    def __init__(self, seed: int, entropy: bytes) -> None:
        self.seed = seed
        self.bucket = entropy[0] >> 4          # high nibble of first byte
        self.parity = entropy[0] & 1           # low bit of first byte
        self.head = entropy[:4].hex()

    def as_dict(self) -> dict:
        return {"seed": self.seed, "bucket": self.bucket,
                "parity": self.parity, "head": self.head}

    def __repr__(self) -> str:
        return (f"Fingerprint(seed={self.seed}, bucket={self.bucket:x}, "
                f"parity={self.parity}, head={self.head})")


def seed_fingerprints(lo: int, hi: int, use_vector: bool = True):
    """Fingerprints for every seed in [lo, hi]."""
    out: list[Fingerprint] = []
    if use_vector and vectorization_available():
        import numpy as np
        arr = np.arange(lo, hi + 1, dtype=np.uint32)
        bufs = batch_entropy_np(arr)
        for k, s in enumerate(range(lo, hi + 1)):
            out.append(Fingerprint(s, bufs[k].tobytes()))
    else:
        for s in range(lo, hi + 1):
            out.append(Fingerprint(s, seed_entropy(s)))
    return out


def bucket_histogram(lo: int, hi: int, use_vector: bool = True) -> list[int]:
    """Count of seeds per entropy[0] high-nibble bucket (16 entries)."""
    hist = [0] * 16
    if use_vector and vectorization_available():
        import numpy as np
        step = 1 << 17
        base = lo
        while base <= hi:
            cnt = min(step, hi - base + 1)
            arr = np.arange(base, base + cnt, dtype=np.uint32)
            first = batch_entropy_np(arr)[:, 0]
            b = (first >> 4).astype(np.int64)
            hc = np.bincount(b, minlength=16)
            for i in range(16):
                hist[i] += int(hc[i])
            base += cnt
    else:
        for s in range(lo, hi + 1):
            hist[seed_entropy(s)[0] >> 4] += 1
    return hist


def checksum_bucket_stats(lo: int, hi: int, use_vector: bool = True) -> dict:
    """Per-bucket totals AND per-bucket BIP-39 checksum-pass counts.

    Diagnostic: shows whether some buckets are richer in valid wallets than
    others (they should not be — uniformity is itself a correctness signal).
    """
    total = [0] * 16
    passed = [0] * 16
    if use_vector and vectorization_available():
        import numpy as np
        step = 1 << 17
        base = lo
        while base <= hi:
            cnt = min(step, hi - base + 1)
            arr = np.arange(base, base + cnt, dtype=np.uint32)
            bufs = batch_entropy_np(arr)
            buckets = (bufs[:, 0] >> 4).astype(np.int64)
            for k in range(cnt):
                bk = int(buckets[k])
                total[bk] += 1
                if hashlib.sha256(bufs[k].tobytes()).digest()[0] % 16 == 0:
                    passed[bk] += 1
            base += cnt
    else:
        for s in range(lo, hi + 1):
            e = seed_entropy(s)
            b = e[0] >> 4
            total[b] += 1
            if hashlib.sha256(e).digest()[0] % 16 == 0:
                passed[b] += 1
    return {"total": total, "passed": passed,
            "pass_rate": [round(p / max(1, t), 5)
                          for p, t in zip(passed, total)]}


def prune_ranges(lo: int, hi: int, keep_buckets: Iterable[int],
                 use_vector: bool = True) -> list[tuple[int, int]]:
    """Split [lo, hi] into maximal sub-ranges whose seeds fall in keep_buckets.

    ⚠️ REDUCED COVERAGE — returns ranges that SKIP non-matching seeds. Only
    for educational simulations where full coverage is intentionally traded
    for speed; the scanner labels such runs clearly.
    """
    keep = {int(b) % 16 for b in keep_buckets}
    ranges: list[tuple[int, int]] = []
    cur_start = None
    for fp in seed_fingerprints(lo, hi, use_vector=use_vector):
        if fp.bucket in keep:
            if cur_start is None:
                cur_start = fp.seed
        else:
            if cur_start is not None:
                ranges.append((cur_start, fp.seed - 1))
                cur_start = None
    if cur_start is not None:
        ranges.append((cur_start, hi))
    return ranges


def known_wallet_fingerprints(seeds: Iterable[int]) -> dict[int, Fingerprint]:
    return {s: Fingerprint(s, seed_entropy(s)) for s in seeds}


def match_targets(candidates: Iterable[Fingerprint],
                  target_heads: Iterable[str]) -> list[Fingerprint]:
    """Candidates whose entropy head matches one of the given hex prefixes."""
    heads = set(target_heads)
    return [c for c in candidates if c.head in heads]
