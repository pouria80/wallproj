"""Statistical property tests for byte streams.

IMPORTANT: these are *statistical* tests only. Passing them never proves a
generator is cryptographically secure; they mainly demonstrate the converse —
that plausible-looking output can come from very low-entropy sources (which is
exactly why the mt19937-with-32-bit-seed bug was not visible in distribution
plots).

Implemented with math/statistics stdlib only (chi-square, monobit, poker,
serial-correlation) so results are reproducible offline.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


@dataclass
class TestResult:
    name: str
    passed: bool
    statistic: float
    p_value: float | None
    threshold_note: str


def chi_square_frequency(data: Sequence[int], alphabet: int = 256) -> TestResult:
    """Uniformity of symbol frequencies over `alphabet` categories."""
    n = len(data)
    if n == 0:
        raise ValueError("empty data")
    if any(not (0 <= x < alphabet) for x in data):
        raise ValueError("symbols outside [0, alphabet)")
    counts = [0] * alphabet
    for x in data:
        counts[x] += 1
    expected = n / alphabet
    stat = sum((c - expected) ** 2 / expected for c in counts)
    df = alphabet - 1
    # Wilson–Hilferty approximation for chi-square CDF
    z = ((stat / df) ** (1 / 3.0) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    p = 1 - _norm_cdf(z)
    return TestResult("chi_square_frequency", p > 0.01, stat, p,
                      "pass if p > 0.01 (heuristic)")


def monobit(data: Sequence[int]) -> TestResult:
    """Balance of 0/1 bits across the stream."""
    bits = _to_bits(data)
    n = len(bits)
    if n == 0:
        raise ValueError("empty data")
    s = sum(1 << 0 if b else 0 for b in bits) * 2 - n  # +1/-1 sum
    stat = abs(s) / math.sqrt(n)
    p = math.erfc(stat / math.sqrt(2))
    return TestResult("monobit", p > 0.01, stat, p, "pass if p > 0.01")


def serial_correlation(data: Sequence[int], lag: int = 1) -> TestResult:
    """Pearson correlation between x[i] and x[i+lag]; ~0 for good streams."""
    if len(data) < lag + 2:
        raise ValueError("not enough data for requested lag")
    xs = list(data[:-lag])
    ys = list(data[lag:])
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    vy = math.sqrt(sum((y - my) ** 2 for y in ys))
    r = cov / (vx * vy) if vx and vy else 0.0
    # two-sided normal approx for |r| under H0
    z = abs(r) * math.sqrt(len(xs))
    p = math.erfc(z / math.sqrt(2))
    return TestResult(f"serial_correlation_lag{lag}", p > 0.01, r, p,
                      "pass if |r|·√n small (p > 0.01)")


def poker_test(data: Sequence[int], m: int = 4, k: int = 16) -> TestResult:
    """Classic poker test on nibbles: groups of m nibbles over a k-symbol alphabet.

    Each group of m consecutive nibbles is classified by the number of *distinct*
    nibble values it contains, giving classes j = 1..m.  Under H0 (uniform,
    independent nibbles) the class probabilities are analytic:

        P(j) = S(m, j) * (k)_j / k**m

    where S is a Stirling number of the second kind and (k)_j the falling
    factorial.  Because every class has strictly positive probability and the
    class counts are multinomial, there are exactly m categories and the
    chi-square statistic carries **m - 1 degrees of freedom** (for the default
    m = 4, k = 16 that is df = 3 — *not* k - 1).  Reference: Knuth, TAOCP
    vol. 2, poker test; Marsaglia, Blumenthal, Fernholz & Vardi (1964).

    Parameter contract:
      * ``m`` must satisfy ``m >= 2``.  With m = 1 every group is trivially of
        class 1, the statistic is identically 0 and df would be 0, which is
        undefined for the chi-square approximation — such input is rejected.
      * ``k`` must equal 16: this implementation derives nibbles from bytes
        (values 0..15), so any other declared alphabet would silently mismatch
        the real data and yield an invalid test.
    """
    if k != 16:
        raise ValueError(
            "k must be 16: the poker test here operates on nibbles extracted "
            "from bytes (alphabet 0..15); other alphabets are not supported"
        )
    if m < 2:
        raise ValueError(
            "m must be >= 2: with m = 1 all groups collapse into a single "
            "class, giving a degenerate test with zero degrees of freedom"
        )
    if m > k:
        raise ValueError("require m <= k")
    nibbles: list[int] = []
    for byte in data:
        if not (0 <= byte <= 255):
            raise ValueError("data must be byte values in [0, 255]")
        nibbles.append(byte & 0xF)
        nibbles.append((byte >> 4) & 0xF)
    n_groups = len(nibbles) // m
    if n_groups == 0:
        raise ValueError("not enough data for poker test")
    groups = [tuple(nibbles[i * m:(i + 1) * m]) for i in range(n_groups)]

    # Observed class counts: v[j] = number of groups with exactly j distinct values
    v = [0] * (m + 1)
    for g in groups:
        v[len(set(g))] += 1

    # Expected class probabilities for m draws (with replacement) from k symbols:
    # P(j distinct) = S(m, j) * (k)_j / k^m.
    def stirling(n_: int, r_: int) -> int:
        dp = [[0] * (r_ + 1) for _ in range(n_ + 1)]
        dp[0][0] = 1
        for i in range(1, n_ + 1):
            for j in range(1, min(i, r_) + 1):
                dp[i][j] = j * dp[i - 1][j] + dp[i - 1][j - 1]
        return dp[n_][r_]

    def falling(nn: int, rr: int) -> int:
        out = 1
        for i in range(rr):
            out *= nn - i
        return out

    km = k ** m
    stat = 0.0
    for j in range(1, m + 1):
        e_j = n_groups * stirling(m, j) * falling(k, j) / km
        stat += (v[j] - e_j) ** 2 / e_j

    df = m - 1  # m multinomial classes with positive probability => m-1 df
    # Wilson–Hilferty approximation for the chi-square upper-tail p-value
    # (safe here because validation guarantees df >= 1).
    z = (((stat / df) ** (1 / 3.0) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
         if stat > 0 else -5.0)
    p = 1 - _norm_cdf(z)
    return TestResult("poker", p > 0.01, stat, p,
                      f"pass if p > 0.01 (chi-square, df={df})")


def entropy_estimate(data: Sequence[int], alphabet: int = 256) -> float:
    """Shannon entropy of the empirical byte distribution, bits/byte."""
    n = len(data)
    if n == 0:
        return 0.0
    counts: dict[int, int] = {}
    for x in data:
        counts[x] = counts.get(x, 0) + 1
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return h


def distinct_ratio(data: Sequence[int]) -> float:
    """Fraction of unique symbols — crude repetition detector."""
    if not data:
        raise ValueError("empty data")
    return len(set(data)) / len(data)


def run_all_tests(data: Sequence[int]) -> list[TestResult]:
    results = [chi_square_frequency(data), monobit(data),
               serial_correlation(data, lag=1), poker_test(data)]
    return results


def _to_bits(data: Sequence[int]) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def _norm_cdf(z: float) -> float:
    return 0.5 * math.erfc(-z / math.sqrt(2))
