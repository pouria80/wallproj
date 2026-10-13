"""Pure, slow but obviously-correct reference MT19937 (full 624-word state).

Used ONLY to validate `fast_mt.py` bit-for-bit. Mirrors std::mt19937:
seed(uint32) init + twist-on-demand generation with cursor semantics.
"""
from __future__ import annotations

_N = 624
_M = 397
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
        for i in range(_N):
            y = (self.mt[i] & _UPPER) | (self.mt[(i + 1) % _N] & _LOWER)
            self.mt[i] ^= self.mt[(i + _M) % _N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= _MASK_A
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


def ref_first_outputs(seed: int, n: int) -> list[int]:
    """First n outputs of a freshly seeded std::mt19937 (reference truth)."""
    g = RefMT19937(seed)
    # libstdc++ mt19937 generates the whole block on first call; our fast path
    # must match this exactly for the first n <= 624 outputs.
    return [g.genrand_uint32() for _ in range(n)]


def ref_entropy_buffer(seed: int) -> bytes:
    """16-byte entropy buffer as wallet-core consumed it (LE uint32 x4)."""
    outs = ref_first_outputs(seed, 4)
    return b"".join(x.to_bytes(4, "little") for x in outs)
