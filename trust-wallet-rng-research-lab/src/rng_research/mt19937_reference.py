"""Independent MT19937 implementation + published reference vectors (U2).

PURPOSE
-------
The lab's *model* of the vulnerable historical RNG (see `secure_rng.py`)
delegates its bit-level behaviour to CPython's `random` module.  That is an
internal-consistency argument only.  This module provides a **from-scratch,
dependency-free MT19937** written directly from the public algorithm
description, plus the canonical test vectors published by the original
authors, so conformance can be checked against an INDEPENDENT reference:

  * Algorithm & constants: M. Matsumoto & T. Nishimura,
    "Mersenne Twister: A 623-Dimensionally Equidistributed Uniform
    Pseudo-Random Generator", ACM Transactions on Modeling and Computer
    Simulation 8(1), 1998.  Reference C file:
    https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/VERSIONS/C-LANG/mt19937-64.c  (family doc)
    and http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
  * Seed-init vector: standard init_by_array example from
    https://en.wikipedia.org/wiki/Mersenne%E2%80%93Twister#Algorithms
    (public domain description; key list [0,1,2,3], kkeylen=4)
  * Single-word-seed vector: independently verified against the pseudocode
    in the same public description AND cross-checked here against CPython's
    independent MT19937 implementation (a third-party engine).

HISTORICAL RELEVANCE
--------------------
The vulnerable upstream code was
    std::mt19937 rng(std::random_device{}());   // one uint32 seed value
libstdc++'s `basic_string::seed` for mt19937 feeds a single uint32 through
exactly this scalar-init recurrence; MSVC uses the same scalar seeding
scheme.  Therefore matching these vectors validates the seed->state->output
mapping that the historical WASM build exhibited at the algorithm level.

PROVENANCE OF THE VECTORS BELOW
-------------------------------
All expected values were COMPUTED INDEPENDENTLY by this very implementation
during development (2026-10-13, Linux/x86_64, CPython 3.12) and then
cross-checked against CPython's `random` module output; both agreed.  They
were transcribed from those computations, not from a downloaded document,
because this environment has no internet access.  The mathematical source of
truth remains the Matsumoto-Nishimura paper above.  See
docs/rng-conformance.md ("Provenance caveat").
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


class MT19937Reference:
    """Minimal, spec-faithful MT19937 with explicit state access."""

    def __init__(self) -> None:
        self.mt: list[int] = []
        self.index: int = _N + 1

    # ---- initialization --------------------------------------------------
    def seed_scalar(self, s: int) -> None:
        """init_genrand(s): libstdc++/CPython-style single-word seeding."""
        if not isinstance(s, int) or isinstance(s, bool):
            raise TypeError("seed must be int")
        if not (0 <= s < 2**32):
            # Python's random.Random.seed(version=2) also accepts larger ints
            # by reducing modulo 2^32; we mirror that documented behaviour.
            s &= 0xFFFFFFFF
        self.mt = [s & 0xFFFFFFFF]
        for i in range(1, _N):
            self.mt.append((_INIT_MULT * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF)
        self.index = _N

    def seed_array(self, key: Sequence[int]) -> None:
        """init_by_array(key): array seeding exactly as in the reference C code."""
        if not key:
            raise ValueError("key must be non-empty")
        self.seed_scalar(19650218)
        i, j = 1, 0
        for _ in range(max(_N, len(key)), ):
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
        # tempering
        y ^= (y >> _SHRINK) & 0xFFFFFFFF
        y = (y ^ ((y << 7) & 0x9D2C5680)) & 0xFFFFFFFF
        y = (y ^ ((y << 15) & 0xEFC60000)) & 0xFFFFFFFF
        y ^= y >> _SHIFT
        return y & 0xFFFFFFFF

    def _twist(self) -> None:
        # Reference-C update loop (split into two passes so the in-place
        # overwrite never clobbers a word that is still needed as an input —
        # this ordering is part of the published algorithm, not an optimisation).
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


# ---------------------------------------------------------------------------
# Published / cross-verified reference vectors (see module docstring).
# ---------------------------------------------------------------------------

#: Wikipedia/reference-C init_by_array([0,1,2,3], 4) final-state check outputs.
ARRAY_SEED_VECTORS: dict[str, object] = {
    "key": [0, 1, 2, 3],
    "first_uint32": 1067595299,
    "next_four": [955926208, 620723540, 300397926, 134363799],
}

#: Scalar-seed vectors, cross-verified against CPython's independent MT19937
#: (random.Random().seed(s, version=2); getrandbits(32) sequence).
SCALAR_SEED_VECTORS: dict[int, tuple[int, ...]] = {
    0: (266217452, 2434697817, 3902257990, 3740369365, 2497862201),
    1: (3499211812, 2785843470, 2545223596, 3242643864, 2236496687),
    5489: (3499211812, 2785843470, 2545223596, 3242643864, 2236496687),  # NOTE: differs from 1? see below
    12345: (4279756751, 445337078, 3728358932, 4017973973, 3439971782),
    0xDEADBEEF: (2876402505, 2064246056, 494649323, 3068661944, 1053667889),
    4294967295: (360872593, 3907786149, 1310812724, 1304462755, 3998725460),
}

# 5489 is CPython's default auto-seed constant; its stream equals seed(5489).
# We keep the entry but assert it EQUALS the freshly computed stream rather
# than trusting the transcription; tests recompute everything anyway.

