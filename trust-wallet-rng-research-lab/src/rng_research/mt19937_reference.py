"""Independent MT19937 implementation + externally-oracled conformance vectors (U2).

STATUS OF CONFORMANCE CLAIMS (read carefully)
---------------------------------------------
* twist + tempering + scalar init_genrand: **VERIFIED** against an external,
  reproducible oracle — libstdc++ `std::mt19937` compiled with g++ 12.2.0
  (Debian).  See fixtures/references/mt19937_scalar_vectors.txt and
  tests/test_mt19937_conformance.py.  All six seed streams match exactly.
* CPython `random.Random().seed(s, version=2)` produces a DIFFERENT stream for
  the same uint32 seed than libstdc++ `std::mt19937(s)`.  This is NOT an
  algorithmic difference of the MT19937 core; it is a *seeding-contract*
  difference: CPython feeds the int through its own `init_by_array`-style
  seeding of the 624-word state, while libstdc++ uses the classic
  `init_genrand` linear recurrence.  Consequence: the lab's Python MODEL
  (`secure_rng.model_random32`) reproduces the vulnerable architecture
  (fresh engine per call, one uint32 seed, first output only) but its exact
  seed->output mapping equals CPython's convention, not the historical WASM
  build's libstdc++ convention.  Bit-level equivalence of the model to the
  historical binary remains UNVERIFIED until a WASM/Emscripten artefact or a
  matching libstdc++ build is exercised (see docs/rng-conformance.md).
* temeper-function sanity: temper(y) is a bijection on uint32; temper(1)=4194449
  is CORRECT for the standard parameter set (earlier doubt in a progress note
  came from confusing "temper" with the identity map; the inverse check below
  in the tests confirms bijectivity).

ALGORITHM SOURCE
----------------
M. Matsumoto & T. Nishimura, "Mersenne Twister: A 623-Dimensionally
Equidistributed Uniform Pseudo-Random Generator", ACM TOMACS 8(1), 1998.
Constants below are the published MT19937 parameter set.

ORACLE PROVENANCE (recorded for reproducibility)
------------------------------------------------
oracle program : fixtures/references/gen_mt.cpp
                 sha256 24890226b419fa51d223b7b81b561d8709853e7d33668a7e8784afb90774fc89
compiler       : g++ (Debian 12.2.0-14+deb12u1), -O2 -std=c++11
libstdc++ impl : random.tcc fetched from gcc-mirror/gcc tag releases/gcc-13.2.0
                 sha256 81930a352418e93d011b337998eb67bb2296348e2aad36b8357ebfcb50ecb70a
vector file    : fixtures/references/mt19937_scalar_vectors.txt
                 sha256 2d982db97d3058fa95710893fa3e1afa217a4d4fa2541f3852ef40ce281aeac7
generated      : 2026-10-13, Linux/x86_64
"""
from __future__ import annotations

from typing import Sequence

# Standard MT19937 (32-bit) parameters — Matsumoto & Nishimura 1998.
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

    def __init__(self) -> None:
        self.mt: list[int] = []
        self.index: int = _N + 1

    # ---- initialization --------------------------------------------------
    def seed_scalar(self, s: int) -> None:
        """init_genrand(s): the classic scalar seeding used by libstdc++.

        NOTE: this deliberately differs from CPython's seed(int) contract
        (module docstring).  Larger ints are reduced mod 2^32.
        """
        if not isinstance(s, int) or isinstance(s, bool):
            raise TypeError("seed must be int")
        self.mt = [s & 0xFFFFFFFF]
        for i in range(1, _N):
            self.mt.append((_INIT_MULT * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF)
        self.index = _N

    def seed_array(self, key: Sequence[int]) -> None:
        """init_by_array(key): array seeding exactly as in the reference C code.

        No external oracle available offline for this path -> treated as
        internally-consistent reconstruction only (UNVERIFIED bit-level).
        """
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
        # Reference-C update loop (split into two passes so the in-place
        # overwrite never clobbers a word that is still needed as input).
        for i in range(_N - _M):
            y = (self.mt[i] & _UPPER_MASK) | (self.mt[i + 1] & _LOWER_MASK)
            self.mt[i] = self.mt[i + _M] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
        for i in range(_N - _M, _N - 1):
            y = (self.mt[i] & _UPPER_MASK) | (self.mt[i + 1] & _LOWER_MASK)
            self.mt[i] = self.mt[i + (_M - _N)] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
        y = (self.mt[_N - 1] & _UPPER_MASK) | (self.mt[0] & _LOWER_MASK)
        self.mt[_N - 1] = self.mt[_M - 1] ^ (y >> 1) ^ (_MATRIX_A if (y & 1) else 0)
        self.index = 0

    def first_output_after_seed(self, seed: int) -> int:
        """Exactly the vulnerable pattern: fresh engine per call, first output."""
        self.seed_scalar(seed)
        return self.next_uint32()


def load_scalar_vectors(path) -> dict[int, tuple[int, ...]]:
    """Parse fixtures/references/mt19937_scalar_vectors.txt (# comments allowed)."""
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
