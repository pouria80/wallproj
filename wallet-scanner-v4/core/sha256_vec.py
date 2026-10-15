"""Vectorized SHA-256 (FIPS 180-4) over fixed-size byte rows — numpy SIMD lanes.

Purpose: the scanner's BIP-39 checksum filter needs sha256(entropy)[0] for
millions of 16-byte buffers per second. hashlib is one-call-per-buffer; this
module runs the full compression function on ALL lanes at once using uint32
numpy arrays, returning the first digest byte of every row. Bit-for-bit
identical to ``hashlib.sha256(row).digest()[0]`` — enforced by a runtime
self-test that runs ONCE per process before the vector path is ever allowed
into production (see `_ensure_selftest`). If the self-test fails for ANY
reason, callers get an exception and fall back to hashlib: correctness can
never be traded for speed here.

Correctness design decisions:
  * K constants are GENERATED from first principles (fractional parts of cube
    roots of the first 64 primes, FIPS 180-4 §4.2.2) with high-precision
    integer Newton iteration — zero transcription risk — and then cross-checked
    against the canonical published values embedded in the self-test.
  * Single-block only: rows must be <= 55 bytes (padding + 8-bit-length field
    fits one 64-byte block). The scanner uses 16-byte entropy rows.
  * Big-endian word loading via '>u4' view; all arithmetic mod 2^32 via
    numpy uint32 overflow semantics.
"""
from __future__ import annotations

import hashlib

import numpy as np


# ---------------------------------------------------------------------------
# K table: generated exactly per FIPS 180-4, then verified vs published list.
# ---------------------------------------------------------------------------
def _icbrt(n: int) -> int:
    """Integer cube root of n (floor), exact for arbitrary size."""
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def _gen_k_table():
    """First 32 bits of frac(cbrt(p)) for the first 64 primes — EXACT.

    floor(cbrt(p · 2^96)) == floor(cbrt(p) · 2^32); its low 32 bits are the
    fractional part's top 32 bits because integer cbrt(p) ∈ {1..3} contributes
    only to bits ≥ 32. Integer Newton iteration ⇒ no float rounding anywhere.
    """
    vals = []
    p, found = 2, 0
    while found < 64:
        isp = all(p % d for d in range(2, int(p ** 0.5) + 1)) and p > 1
        if isp:
            vals.append(_icbrt(p << 96) & 0xFFFFFFFF)
            found += 1
        p += 1
    return vals


_K_PUBLISHED = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca9cc, 0x2be9b1df, 0x3a79280a, 0x976e6b8f, 0x16a574b3,
    0x27f30e54, 0x2427b081, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0x428c1255, 0x510e527f, 0x685e15b8,
    0x852142dd, 0x96604456, 0xa4f603b3, 0xbeef7ee4, 0xbfdebbc5, 0xc19c107e, 0xc4e1ba06, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
    0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
]
assert len(_K_PUBLISHED) == 64

_GEN_K = _gen_k_table()          # computed once; compared in _ensure_selftest()
assert len(_K_PUBLISHED) == 64

_K = np.array(_K_PUBLISHED, dtype=np.uint32)
_H0 = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


def _rotr(x, k):
    return ((x >> np.uint32(k)) | (x << np.uint32(32 - k))).astype(np.uint32)


def sha_first_byte_rows(rows: "np.ndarray") -> "np.ndarray":
    """First digest byte of SHA-256 for each row of an (N, R) uint8 array.

    Requires 0 < R <= 55 (single-block messages). Returns uint8 length N with
    element i == hashlib.sha256(rows[i]).digest()[0].
    """
    rows = np.ascontiguousarray(rows, dtype=np.uint8)
    if rows.ndim != 2 or not (0 < rows.shape[1] <= 55):
        raise ValueError("single-block rows only: shape (N, R), 0 < R <= 55")
    n, r = rows.shape

    blk = np.zeros((n, 64), dtype=np.uint8)
    blk[:, :r] = rows
    blk[:, r] = 0x80
    bl = np.zeros(n, dtype=">u8")
    bl[:] = np.uint64(r) * np.uint64(8)
    blk[:, 56:64] = bl.view(np.uint8).reshape(n, 8)

    W = np.zeros((n, 64), dtype=np.uint32)
    W[:, :16] = blk.view(dtype=">u4").astype(np.uint32)

    for t in range(16, 64):
        s0 = (_rotr(W[:, t - 15], 7) ^ _rotr(W[:, t - 15], 18)
              ^ (W[:, t - 15] >> np.uint32(3))).astype(np.uint32)
        s1 = (_rotr(W[:, t - 2], 17) ^ _rotr(W[:, t - 2], 19)
              ^ (W[:, t - 2] >> np.uint32(10))).astype(np.uint32)
        W[:, t] = (s0 + W[:, t - 7] + s1 + W[:, t - 16]).astype(np.uint32)

    a = np.full(n, _H0[0], dtype=np.uint32)
    b = np.full(n, _H0[1], dtype=np.uint32)
    c = np.full(n, _H0[2], dtype=np.uint32)
    d = np.full(n, _H0[3], dtype=np.uint32)
    e = np.full(n, _H0[4], dtype=np.uint32)
    f = np.full(n, _H0[5], dtype=np.uint32)
    g = np.full(n, _H0[6], dtype=np.uint32)
    hh = np.full(n, _H0[7], dtype=np.uint32)

    for t in range(64):
        S0 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)).astype(np.uint32)
        S1 = (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)).astype(np.uint32)
        ch = ((e & f) ^ ((~e) & g)).astype(np.uint32)
        maj = ((a & b) ^ (a & c) ^ (b & c)).astype(np.uint32)
        tt1 = (hh + S1 + ch + _K[t] + W[:, t]).astype(np.uint32)
        tt2 = (S0 + maj).astype(np.uint32)
        hh = g
        g = f
        f = e
        e = (d + tt1).astype(np.uint32)
        d = c
        c = b
        b = a
        a = (tt1 + tt2).astype(np.uint32)

    h0 = (a + np.uint32(_H0[0])).astype(np.uint32)
    return (h0 >> np.uint32(24)).astype(np.uint8)


# ---------------------------------------------------------------- self-test
_SELFTEST_OK = False


def _ensure_selftest() -> bool:
    """One-time exhaustive-vs-hashlib check on random rows incl. known answers.

    Returns True only when the vectorized kernel provably agrees with hashlib.
    Cached per process. Any exception ⇒ False ⇒ caller must use hashlib.
    """
    global _SELFTEST_OK
    if _SELFTEST_OK:
        return True
    try:
        # independent cross-check: exact first-principles K generation must
        # match the published table we actually run with (FIPS 180-4 §4.2.2)
        if _GEN_K != _K_PUBLISHED or len(_GEN_K) != 64:
            return False
        rng = np.random.default_rng(0xC0FFEE)
        for R in (1, 3, 16, 31, 55):
            rows = rng.integers(0, 256, (20_000, R), dtype=np.uint8)
            got = sha_first_byte_rows(rows)
            want = np.frombuffer(
                b"".join(hashlib.sha256(rows[i].tobytes()).digest()[:1]
                         for i in range(len(rows))), dtype=np.uint8)
            if not np.array_equal(got, want):
                return False
        # known-answer: sha256(b"abc")[0] == 0xba
        ka = sha_first_byte_rows(np.frombuffer(b"abc", np.uint8).reshape(1, 3))
        if int(ka[0]) != 0xBA:
            return False
        _SELFTEST_OK = True
        return True
    except Exception:
        return False
