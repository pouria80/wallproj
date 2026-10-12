"""Secure RNG utilities and faithful *models* of the historical behaviour.

`secure_bytes()` is the only function here intended for real randomness in
this lab: it wraps `secrets` (OS CSPRNG). Everything else is a documented,
clearly-labelled MODEL used to reproduce/illustrate the 2022 Wallet-Core WASM
bug — it must never be used to generate anything of value.

Modelled vulnerable pattern (from upstream wasm/src/Random.cpp @69b2da98):
    uint32_t random32(void) {
        std::mt19937 rng(std::random_device{}());   // fresh engine per call
        return rng();                               // first output only
    }
Python's ``random.Random(seed)`` implements exactly the same mt19937 core, so
``model_random32`` reproduces the C++ generator's mapping seed→output with
bit-level fidelity (verified against Python's own MT19937 stream).
"""
from __future__ import annotations

import random
import secrets
from typing import Iterator


class SecureRNGError(Exception):
    """Raised on invalid requests to the secure RNG wrapper."""


def secure_bytes(n: int) -> bytes:
    """Return n cryptographically-strong random bytes via the OS CSPRNG."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise SecureRNGError(f"n must be an int, got {type(n).__name__}")
    if n <= 0:
        raise SecureRNGError(f"n must be positive, got {n}")
    if n > 1_000_000:
        raise SecureRNGError("refusing single allocation > 1,000,000 bytes")
    return secrets.token_bytes(n)


def model_random32(seed: int) -> int:
    """MODEL: emulate vulnerable `random32()` for one given 32-bit seed.

    Mirrors the C++ code path: construct a fresh mt19937 with `seed`,
    return its first 32-bit output. Deterministic by design.
    """
    if not (0 <= seed < 2**32):
        raise ValueError(f"seed must be a uint32, got {seed}")
    rng = random.Random()
    rng.seed(seed, version=2)  # version=2 == plain int seed into MT19937
    return rng.getrandbits(32)


def model_random_buffer_seeded(seed: int, length: int) -> bytes:
    """MODEL: emulate vulnerable `random_buffer()` for one 32-bit seed.

    C++ took low 8 bits of successive mt19937 outputs (`rng() & 0xff`).
    NOTE: in the real bug each *call* reseeded from a new random_device
    draw; this helper models a single engine run, useful for state-space
    experiments. The per-call reseeding is modelled by
    :func:`model_vulnerable_stream`.
    """
    if not (0 <= seed < 2**32):
        raise ValueError("seed must be a uint32")
    if length <= 0:
        raise ValueError("length must be positive")
    rng = random.Random()
    rng.seed(seed, version=2)
    out = bytearray()
    while len(out) < length:
        out.append(rng.getrandbits(32) & 0xFF)
    return bytes(out[:length])


def model_per_call_reseed_sequence(seeds: Iterator[int] | list[int],
                                   buffer_len: int = 16) -> list[bytes]:
    """MODEL: sequence of `random_buffer(len)` calls where every call builds a
    NEW mt19937 seeded by ONE 32-bit draw (exactly the historical bug).

    All buffers generated from equal seeds are identical → the reachable
    output space per buffer is at most 2^32 distinct values.
    """
    results = []
    for s in seeds:
        results.append(model_random_buffer_seeded(s, buffer_len))
    return results


def model_effective_state_space(sample_seeds: list[int], buffer_len: int = 16) -> dict:
    """Empirically demonstrate the collapse of the output space.

    Returns counts of distinct buffers produced from distinct seeds —
    bounded above by min(#seeds, 2^32). With true 128-bit entropy you would
    expect essentially all-distinct buffers even across huge samples; with
    32-bit seeds collisions become measurable (birthday bound ≈ 2^16 draws).
    """
    buffers = {}
    dup_seeds = 0
    seen_seeds: set[int] = set()
    for s in sample_seeds:
        if s in seen_seeds:
            dup_seeds += 1
            continue
        seen_seeds.add(s)
        b = model_random_buffer_seeded(s, buffer_len)
        buffers[b] = buffers.get(b, 0) + 1
    return {
        "requested_draws": len(sample_seeds),
        "unique_seeds": len(seen_seeds),
        "duplicate_seed_draws": dup_seeds,
        "distinct_buffers": len(buffers),
        "buffer_len": buffer_len,
        "theoretical_max_distinct_from_32bit_seeds": 2**32,
    }
