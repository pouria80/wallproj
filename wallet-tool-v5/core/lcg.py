"""Time-seeded Linear Congruential Generators (PHP mt_rand-era / Java Random).

Many 2011-2015 wallets and faucet tools written in PHP/Java (and various
"brainwallet" scripts) derived their private keys from a classic LCG seeded
with the system clock.  Their search space is tiny (a few billion ms seeds at
most, often far less), so success probability per swept second is high.

Models implemented (bit-exact):

  * glibc `random()` TYPE_3 additive feedback — NOT an LCG, but the standard
    "rand()" of C daemons; kept here because several PHP extensions used it.
  * Java `java.util.Random` — 48-bit LCG:  s = (s*0x5DEECE66D + 0xB) & 2^48-1
        next(bits) = s >> (48-bits)
        nextInt()  = next(32) sign-extended ; nextLong = (next(32)<<32)|next(32)
    seeding: s = (seed ^ 0x5DEECE66D) & mask48
  * ANSI-C / MSVC `rand()` — 31-bit LCG family (MSVC: s = s*214013+2531011,
    rand = (s>>16)&0x7FFF)
  * Numerical-Recipes / Borland LCG:  s = s*1664525 + 1013904223 (mod 2^32)
  * PHP's old `mt_rand` is MT — handled by the MT engine; `srand/rand` on
    Windows used MSVC above.

Entropy extraction patterns seen historically:
  - take top bytes of each nextInt() (big-endian) until buffer full
  - `(rand()%256)` per byte (MSVC family)
  - Java: SecureRandom *fallback* was real RNG, but many custom key-gen
    snippets did `new BigInteger(256, new Random(seed))` with seed=time.
    We model BigInteger(nbits, rnd): repeatedly nextInt -> unsigned 32 bits,
    fill big-endian, then shift down & mask to nbits, set top bit if needed
    (per java.security.SecureRandom/Random contract: value in [0, 2^nbits)).
"""
from __future__ import annotations

import struct
from typing import Iterable, Iterator

M32 = 0xFFFFFFFF
M48 = (1 << 48) - 1
JAVA_MULT = 0x5DEECE66D
JAVA_ADD = 0xB
MSVC_MULT = 214013
MSVC_ADD = 2531011
NR_MULT = 1664525
NR_ADD = 1013904223


class JavaRandom:
    """Exact model of java.util.Random."""

    def __init__(self, seed: int):
        self.s = (seed ^ JAVA_MULT) & M48

    def next(self, bits: int) -> int:
        self.s = (self.s * JAVA_MULT + JAVA_ADD) & M48
        return self.s >> (48 - bits)

    def next_int(self) -> int:
        v = self.next(32)
        return v - (1 << 32) if v >= (1 << 31) else v      # signed

    def next_long(self) -> int:
        return (self.next(32) << 32) | self.next(32)

    def next_bytes(self, n: int) -> bytes:
        """n bytes, big-endian top bytes of successive nextInt() words."""
        out = bytearray()
        while len(out) < n:
            out += struct.pack(">I", self.next(32))
        return bytes(out[:n])

    def big_integer(self, nbits: int) -> bytes:
        """java.math.BigInteger(numBits, Random) semantics (JDK source).

        value = numBits worth of nextInt() words, big-endian; then
        `value >>>= excessBits` where excess = 32*words - numBits, so the
        result is uniformly in [0, 2^numBits).  Returns ceil(nbits/8) bytes.
        """
        words = (nbits + 31) // 32
        acc = 0
        for _ in range(words):
            acc = (acc << 32) | self.next(32)              # unsigned words
        excess = words * 32 - nbits
        acc >>= excess
        return acc.to_bytes((nbits + 7) // 8, "big")


class MSVCRand:
    """ANSI-C/MSVC rand(): 32-bit state LCG, rand = (state>>16)&0x7FFF."""

    def __init__(self, seed: int):
        self.s = seed & M32

    def rand(self) -> int:
        self.s = (self.s * MSVC_MULT + MSVC_ADD) & M32
        return (self.s >> 16) & 0x7FFF

    def next_bytes_mod(self, n: int) -> bytes:
        """Historical pattern: byte = rand() % 256 (biased, but that's what ran)."""
        return bytes(self.rand() % 256 for _ in range(n))

    def next_bytes_top(self, n: int) -> bytes:
        """Pattern: two rand() calls per 16-bit word, big-endian packing."""
        out = bytearray()
        while len(out) < n:
            w = (self.rand() << 15) | self.rand()          # 30-bit word
            out += struct.pack(">I", w)
        return bytes(out[:n])


class NRLCG:
    """Numerical Recipes / Borland / VAX-family uint32 LCG."""

    def __init__(self, seed: int):
        self.s = seed & M32

    def next(self) -> int:
        self.s = (self.s * NR_MULT + NR_ADD) & M32
        return self.s

    def next_bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += struct.pack(">I", self.next())
        return bytes(out[:n])


# Historical note: glibc random() TYPE_3 was used by some C-based wallet
# daemons; it is an additive-feedback generator, not an LCG.  Out of scope for
# the scan engine (Java/MSVC/NR LCGs cover the PHP/Java wallet corpus).


def time_seed_lcg(t_seconds: int, variant: str, salt: int = 0) -> Iterator[bytes]:
    """Yield candidate 32-byte entropy buffers for one wall-clock second.

    Covers the practical seeding mistakes:
      * seed = epoch seconds                    (small space: sweep in engine)
      * seed = epoch seconds ± micro-second guesses (salt offsets)
    """
    base = t_seconds + salt
    if variant == "java":
        yield JavaRandom(base).big_integer(256)
        yield JavaRandom(base).next_bytes(32)
    elif variant == "msvc_mod":
        yield MSVCRand(base).next_bytes_mod(32)
    elif variant == "msvc_top":
        yield MSVCRand(base).next_bytes_top(32)
    elif variant == "nr":
        yield NRLCG(base).next_bytes(32)
    else:
        raise ValueError(f"unknown LCG variant {variant!r}")


VARIANTS = ("java", "msvc_mod", "msvc_top", "nr")
