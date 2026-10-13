"""MT19937 core — bit-exact model of libstdc++ std::mt19937 (CVE-2023-31290).

Conformance: verified against the externally-oracled vectors produced by
g++ 12.2.0 (libstdc++ <random>) — tests/mt19937_scalar_vectors.txt.
Algorithm source: Matsumoto & Nishimura, ACM TOMACS 8(1), 1998.

Reused byte-for-byte from wallet-scanner-v2 (independently validated there);
see trust-wallet-rng-research-lab/docs/rng-conformance.md for provenance.
"""
from __future__ import annotations

from typing import Sequence

_N = 624
_M = 397
_MATRIX_A = 0x9908B0DF
_UPPER_MASK = 0x80000000
_LOWER_MASK = 0x7FFFFFFF
_INIT_MULT = 1812433253
_SHRINK = 11
_SQR_B = 0x9D2C5680
_SQR_C = 0xEFC60000
_SHIFT = 18


def temper(y: int) -> int:
    """Standard MT19937 output tempering (bijection on uint32)."""
    y ^= (y >> _SHRINK) & 0xFFFFFFFF
    y = (y ^ ((y << 7) & _SQR_B)) & 0xFFFFFFFF
    y = (y ^ ((y << 15) & _SQR_C)) & 0xFFFFFFFF
    y ^= y >> _SHIFT
    return y & 0xFFFFFFFF


class MT19937Reference:
    """Minimal, spec-faithful MT19937 with explicit state access."""

    __slots__ = ("mt", "index")

    def __init__(self) -> None:
        self.mt: list[int] = []
        self.index: int = _N + 1

    # ---- initialization --------------------------------------------------
    def seed_scalar(self, s: int) -> None:
        """init_genrand(s): the classic scalar seeding used by libstdc++.

        NOTE: deliberately differs from CPython's seed(int) contract.
        Larger ints are reduced mod 2^32.
        """
        if not isinstance(s, int) or isinstance(s, bool):
            raise TypeError("seed must be int")
        mt = [s & 0xFFFFFFFF]
        append = mt.append
        mult = _INIT_MULT
        for i in range(1, _N):
            prev = mt[i - 1]
            append((mult * (prev ^ (prev >> 30)) + i) & 0xFFFFFFFF)
        self.mt = mt
        self.index = _N

    def seed_array(self, key: Sequence[int]) -> None:
        """init_by_array(key): array seeding exactly as in the reference C code."""
        if not key:
            raise ValueError("key must be non-empty")
        self.seed_scalar(19650218)
        i, j = 1, 0
        for _ in range(max(_N, len(key))):
            self.mt[i % _N] ^= ((self.mt[(i - 1) % _N] ^ (self.mt[(i - 1) % _N] >> 30)) * 1664525) & 0xFFFFFFFF
            self.mt[i % _N] = (self.mt[i % _N] + key[j % len(key)] + j) & 0xFFFFFFFF
            i += 1
            j += 1
            if i % _N == 0:
                i = 1
        for _ in range(_N - 1):
            self.mt[i % _N] ^= ((self.mt[(i - 1) % _N] ^ (self.mt[(i - 1) % _N] >> 30)) * 1566083941) & 0xFFFFFFFF
            self.mt[i % _N] = (self.mt[i % _N] - i) & 0xFFFFFFFF
            i += 1
            if i % _N == 0:
                i = 1
        self.mt[0] = 0x80000000  # MSB ensures non-zero state

    # ---- generation ------------------------------------------------------
    def next_uint32(self) -> int:
        if self.index >= _N:
            self._twist()
        y = self.mt[self.index]
        self.index += 1
        return temper(y)

    def _twist(self) -> None:
        mt = self.mt
        for i in range(_N - _M):
            y = (mt[i] & _UPPER_MASK) | (mt[i + 1] & _LOWER_MASK)
            mt[i] = mt[i + _M] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
        for i in range(_N - _M, _N - 1):
            y = (mt[i] & _UPPER_MASK) | (mt[i + 1] & _LOWER_MASK)
            mt[i] = mt[i + (_M - _N)] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
        y = (mt[_N - 1] & _UPPER_MASK) | (mt[0] & _LOWER_MASK)
        mt[_N - 1] = mt[_M - 1] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
        self.index = 0

    def first_output_after_seed(self, seed: int) -> int:
        """Exactly the vulnerable pattern: fresh engine per call, first output."""
        self.seed_scalar(seed)
        return self.next_uint32()


def load_scalar_vectors(path) -> dict[int, tuple[int, ...]]:
    """Parse tests/mt19937_scalar_vectors.txt (# comments allowed)."""
    from pathlib import Path
    vecs: dict[int, tuple[int, ...]] = {}
    text = Path(path).read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [int(x) for x in line.split()]
        if len(parts) != 6:
            raise ValueError(f"malformed vector line: {line!r}")
        vecs[parts[0]] = tuple(parts[1:])
    if not vecs:
        raise ValueError("no vectors found")
    return vecs
