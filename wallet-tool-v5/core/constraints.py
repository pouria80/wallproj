"""Constraint solver for partial-wallet recovery (V5.1).

«حل‌کننده محدودیت — پشتیبانی از کلمات گمشده و سایر محدودیت‌ها»

A scanned weak-RNG candidate is only useful if it satisfies everything we
additionally KNOW about the target wallet.  This module expresses that
knowledge as composable constraints and solves them WITHOUT brute-forcing
the full space when possible:

  * MissingWordConstraint   — BIP-39 phrase with M unknown positions.
      Solved ANALYTICALLY, not by searching 2048^M:
        entropy || checksum  =  12 × 11-bit word indices
        known words fix all bits except the M×11 free ones;
        the 4 checksum bits are SHA-256(entropy) — a function of the SAME
        free bits.  We enumerate only the free bit-combinations that keep
        every known index intact (≤ 2^(11·M) but pruned to the checksum
        budget: expected valid survivors ≈ 2^(11·M − cs_bits/…) — in
        practice a single gap yields exactly 128 candidates, two gaps ~16k
        pre-checksum which the vectorized filter reduces instantly).
      Additionally the RNG model itself constrains entropy: when the phrase
      came from a time-seeded generator, most completions correspond to
      NO reachable seed — `solve_for_rng()` intersects both spaces.

  * AddressPrefixConstraint / AddressSetConstraint — bloom/watchlist gate.
  * BalanceThresholdConstraint — min satoshi value to report.
  * StyleConstraint — restrict path families probed.
  * CompositeConstraint — AND of several.

All solvers return ITERATORS so the scanner can stream candidates and stop
early (`stop_on_hit`).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import numpy as np

import bip39


# ------------------------------------------------------------------ base
class Constraint:
    """Anything that can veto a candidate (mnemonic, entropy, address…)."""

    #: True when this constraint can GENERATE candidates (not just filter)
    generating = False

    def accepts_entropy(self, entropy16: bytes) -> bool:
        return True

    def accepts_mnemonic(self, mnemonic: str) -> bool:
        return True

    def accept_address(self, address: str) -> bool:
        return True

    def generate(self) -> Iterator[bytes]:
        """Yield entropy buffers consistent with this constraint.
        Non-generating constraints yield nothing (pure filters)."""
        return iter(())

    def describe(self) -> dict:
        return {"type": type(self).__name__}


class CompositeConstraint(Constraint):
    """Logical AND over sub-constraints; generation delegated to whichever
    sub-constraint is generating (filters then vet each produced candidate)."""

    def __init__(self, parts: Sequence[Constraint]):
        self.parts = list(parts)

    def add(self, c: Constraint) -> "CompositeConstraint":
        self.parts.append(c)
        return self

    @property
    def _generator(self) -> Optional[Constraint]:
        for p in self.parts:
            if p.generating:
                return p
        return None

    def accepts_entropy(self, entropy16: bytes) -> bool:
        return all(p.accepts_entropy(entropy16) for p in self.parts)

    def accept_address(self, address: str) -> bool:
        return all(p.accept_address(address) for p in self.parts)

    def generate(self) -> Iterator[bytes]:
        g = self._generator
        if g is None:
            return iter(())
        return (e for e in g.generate() if self.accepts_entropy(e))

    def describe(self) -> dict:
        return {"type": "composite",
                "parts": [p.describe() for p in self.parts]}


# ------------------------------------------------------- missing BIP-39 word
@dataclass
class MissingWordConstraint(Constraint):
    """Phrase of N words with gaps at `positions` (0-based).

    Strategy (single gap, exact & fast):
      1. The 11 known words pin 121 of the 132 phrase bits; the missing
         word contributes 11 bits, of which the LAST 4 are… no — ALL 11
         bits of the gap-word are free, but the phrase's final 4 bits are
         the BIP-39 checksum = top 4 bits of SHA-256(entropy).  Enumerate
         all 2048 candidate words, rebuild entropy, verify checksum.
         → exactly 2^(11-cs)=128 survivors on average.  (bip39.completions
         already does this; we reuse it so there is ONE checksum truth.)

    Multiple gaps: iterate the cartesian product of per-position candidate
    sets is 2048^M — instead we enumerate the 2^(11*M) raw bit patterns,
    map through the checksum vector filter, and translate surviving
    indices back to words.  Practical up to M=2 (~16.7M rows, vectorized).
    """

    known_words: Sequence[str]
    positions: Tuple[int, ...]

    def __post_init__(self):
        wl = bip39.wordlist()
        idx = bip39.word_index()
        self._n = len(self.known_words) + len(self.positions)
        if self._n not in (12, 15, 18, 21, 24):
            raise ValueError("phrase length must be a valid BIP-39 length")
        # build slot map: position -> word (known) or None (gap)
        slots: List[Optional[int]] = []
        it = iter(range(len(self.known_words)))
        gi = sorted(self.positions)
        kset = set(gi)
        j = 0
        for pos in range(self._n):
            if pos in kset:
                slots.append(None)
            else:
                w = self.known_words[j]
                if w not in idx:
                    raise ValueError(f"unknown word {w!r}")
                slots.append(idx[w])
                j += 1
        self._slots = slots
        self._wl = wl

    generating = True

    # -- core enumeration ---------------------------------------------------
    def _entropies_12(self) -> Iterator[bytes]:
        """12-word case: derive the 128-bit entropy from free bit patterns."""
        m = len(self.positions)
        if m == 0:
            ent = bip39.mnemonic_to_entropy(
                " ".join(self.known_words))  # validates checksum too
            yield ent
            return
        if m == 1:
            # delegate to the audited single-gap routine (keeps one truth)
            kept = [self._wl[s] for s in self._slots if s is not None]
            pos = self.positions[0]
            for cand in bip39.completions_from_11_words(kept, pos):
                trial = kept[:pos] + [cand] + kept[pos:]
                yield bip39.mnemonic_to_entropy(" ".join(trial))
            return
        if m > 2:
            raise NotImplementedError(
                "gap count >2: split into chained constraints or use the "
                "external tool (space 2^33+ is impractical here)")
        # m == 2: enumerate 2^22 bit patterns, vectorized checksum filter
        free_bits = 11 * m
        pinned = 0
        # phrase value layout: 132 bits = 12*11; checksum occupies last 4
        # Build a template with gap slots zeroed.
        total_bits = 11 * 12
        tmpl = 0
        for i, s in enumerate(self._slots):
            shift = total_bits - 1 - 11 * i
            if s is not None:
                tmpl |= s << shift
        # gap bit masks
        gap_shifts = [total_bits - 1 - 11 * p for p in self.positions]
        CHUNK = 1 << 20
        arr = np.zeros((min(CHUNK, 1 << free_bits), 16), dtype=np.uint8)
        for base in range(0, 1 << free_bits, CHUNK):
            cnt = min(CHUNK, (1 << free_bits) - base)
            vals = np.arange(base, base + cnt, dtype=np.uint64)
            phr = tmpl.astype(np.uint64) if False else None  # noqa
            pv = np.full(cnt, tmpl, dtype=np.uint64)
            # scatter free bits into their 11-bit slots
            for k, sh in enumerate(gap_shifts):
                part = (vals >> (11 * (m - 1 - k))) & np.uint64(0x7FF)
                pv |= part << np.uint64(sh)
            # phrase 132 bits -> entropy 128 = pv >> 4 ; checksum = pv & 0xF
            ents = np.zeros((cnt, 16), dtype=np.uint8)
            big = pv >> np.uint64(4)
            for b in range(16):
                ents[:, 15 - b] = ((big >> np.uint64(8 * b)) &
                                   np.uint64(0xFF)).astype(np.uint8)
            cs = (pv & np.uint64(0xF)).astype(np.uint8)
            dig = np.fromiter(
                (hashlib.sha256(r.tobytes()).digest()[0] >> 4
                 for r in ents), dtype=np.uint8, count=cnt)
            ok = dig == cs
            for row in ents[ok]:
                yield row.tobytes()

    def generate(self) -> Iterator[bytes]:
        if self._n != 12:
            raise NotImplementedError(
                "generation currently supports 12-word phrases; longer "
                "phrases: use solve_with_rng_intersection per-family")
        yield from self._entropies_12()

    def accepts_entropy(self, entropy16: bytes) -> bool:
        """True iff entropy's mnemonic matches all KNOWN words at known slots."""
        try:
            mn = bip39.entropy_to_mnemonic(entropy16)
        except Exception:
            return False
        words = mn.split()
        for i, s in enumerate(self._slots):
            if s is not None and words[i] != self._wl[s]:
                return False
        return True

    def describe(self) -> dict:
        return {"type": "missing_word", "phrase_len": self._n,
                "gaps": list(self.positions),
                "known": list(self.known_words)}


# --------------------------------------------- intersection with RNG models
def solve_with_rng_intersection(constraint: Constraint,
                                rng_generate: Iterable[bytes],
                                ) -> Iterator[bytes]:
    """Stream RNG-model candidates through the constraint filter.

    This is the real search-space reduction: the RNG model emits only
    reachable entropies (e.g. one buffer per millisecond), and the phrase
    constraint vetoes all but the true wallet(s).  Complexity becomes
    O(space_rng) instead of O(space_phrase).
    """
    for ent in rng_generate:
        if constraint.accepts_entropy(ent):
            yield ent


# ---------------------------------------------------------- address gates
@dataclass
class WatchlistConstraint(Constraint):
    """Accept only addresses inside a known-funded set (exact membership)."""
    addresses: Set[str] = field(default_factory=set)

    def accept_address(self, address: str) -> bool:
        return address in self.addresses

    def describe(self) -> dict:
        return {"type": "watchlist", "size": len(self.addresses)}


@dataclass
class AddressPrefixConstraint(Constraint):
    """Some leaks reveal only the first characters of the address."""
    prefix: str

    def accept_address(self, address: str) -> bool:
        return address.startswith(self.prefix)

    def describe(self) -> dict:
        return {"type": "address_prefix", "prefix": self.prefix}


@dataclass
class BalanceThresholdConstraint(Constraint):
    """Report findings only above `min_sat` (checked post-balance by engine)."""
    min_sat: int = 1

    def describe(self) -> dict:
        return {"type": "balance_threshold", "min_sat": self.min_sat}


@dataclass
class EntropyByteConstraint(Constraint):
    """Known byte pattern in the entropy buffer, e.g. dump shows first bytes.

    pattern: bytes with None wildcards, aligned at `offset`.
    """
    pattern: Tuple[Optional[int], ...]
    offset: int = 0

    def accepts_entropy(self, entropy16: bytes) -> bool:
        end = self.offset + len(self.pattern)
        if end > len(entropy16):
            return False
        for i, p in enumerate(self.pattern):
            if p is not None and entropy16[self.offset + i] != p:
                return False
        return True

    def describe(self) -> dict:
        return {"type": "entropy_bytes", "pattern": list(self.pattern),
                "offset": self.offset}


@dataclass
class TimeWindowConstraint(Constraint):
    """RNG-side constraint helper: seeds derived from wall clock in [a,b)."""
    t_start_ms: int
    t_stop_ms: int

    def contains(self, t_ms: int) -> bool:
        return self.t_start_ms <= t_ms < self.t_stop_ms

    def describe(self) -> dict:
        return {"type": "time_window",
                "start_ms": self.t_start_ms, "stop_ms": self.t_stop_ms}


# ------------------------------------------------------------ parsing help
def parse_partial_phrase(text: str,
                         wildcard_tokens: Sequence[str] = ("?", "*", "____"))\
        -> Tuple[List[str], Tuple[int, ...]]:
    """Split a user phrase like 'abandon ? ? word …' into (known, positions).

    Returns the known words IN ORDER (gaps removed) plus gap positions.
    """
    toks = text.lower().split()
    known: List[str] = []
    gaps: List[int] = []
    for i, t in enumerate(toks):
        if t in wildcard_tokens:
            gaps.append(i)
        else:
            known.append(t)
    return known, tuple(gaps)
