"""Pure, slow but obviously-correct reference MT19937 (full 624-word state).

CRITICAL SEMANTICS (fixed after the Windows conformance run exposed a wrong
twist): std::mt19937 (libstdc++) and Makino's mt19937ar.c use the CANONICAL
"generate" twist — each word is REPLACED by

    m'[i] = m[(i+M) mod N] ^ (y_i >> 1) ^ (A if y_i odd else 0)
    y_i   = (m[i] & UPPER) | (m[i+1] & LOWER)          (ORIGINALS only)

NOT the in-place XOR chain `m[i] ^= m[i+M] ...` executed left-to-right. The
old implementation used the XOR-in-place form, which diverges from libstdc++
from output #2 onward for almost every seed — it failed tests/T1 against the
C++ oracle vectors. Verified byte-for-byte against
tests/mt19937_scalar_vectors.txt (g++ 12.2 libstdc++ oracle, sha256-stamped).

Used ONLY to validate `fast_mt.py` bit-for-bit. Mirrors std::mt19937:
seed(uint32) init_genrand + full-block twist on first draw.
"""
from __future__ import annotations

_N = 624
_M = 397
_NM = _N - _M            # 227
_MASK_A = 0x9908B0DF
_UPPER = 0x80000000
_LOWER = 0x7FFFFFFF
_FULL = 0xFFFFFFFF


class RefMT19937:
    def __init__(self, seed: int) -> None:
        self.mt = [0] * _N
        self.mti = _N + 1
        self.seed(seed)

    def seed(self, s: int) -> None:
        self.mt[0] = s & _FULL
        for i in range(1, _N):
            prev = self.mt[i - 1]
            self.mt[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & _FULL
        self.mti = _N

    def _twist(self) -> None:
        """Canonical generate() twist computed from ORIGINAL words only."""
        m = self.mt
        orig = m[:]                       # snapshot of originals (obvious & exact)
        for i in range(_NM):              # i = 0 .. 226 : source m[i+397]
            y = (orig[i] & _UPPER) | (orig[i + 1] & _LOWER)
            m[i] = orig[i + _M] ^ (y >> 1) ^ (_MASK_A if y & 1 else 0)
        for i in range(_NM, _N - 1):      # i = 227 .. 622 : source m[i-227]
            y = (orig[i] & _UPPER) | (orig[i + 1] & _LOWER)
            m[i] = orig[i - _NM] ^ (y >> 1) ^ (_MASK_A if y & 1 else 0)
        y = (orig[_N - 1] & _UPPER) | (orig[0] & _LOWER)   # i = 623 wraps to m[0]
        m[_N - 1] = orig[_M - 1] ^ (y >> 1) ^ (_MASK_A if y & 1 else 0)
        self.mti = 0

    def genrand_uint32(self) -> int:
        if self.mti >= _N:
            self._twist()
        y = self.mt[self.mti]
        self.mti += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & _FULL


# Backwards-compatible alias: earlier revisions of the test-suite imported
# `MT19937Reference`; keep the name so old scripts keep working.
MT19937Reference = RefMT19937


def ref_first_outputs(seed: int, n: int) -> list[int]:
    """First n outputs of a freshly seeded std::mt19937 (reference truth)."""
    g = RefMT19937(seed)
    return [g.genrand_uint32() for _ in range(n)]


def ref_entropy_buffer(seed: int) -> bytes:
    """16-byte entropy buffer exactly as vulnerable wallet-core consumed it:
    random_buffer() called rng() once PER BYTE → low byte of each successive
    tempering output (see wasm/src/Random.cpp@69b2da98)."""
    g = RefMT19937(seed)
    return bytes(g.genrand_uint32() & 0xFF for _ in range(16))
