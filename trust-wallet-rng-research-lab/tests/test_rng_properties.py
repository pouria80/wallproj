import math
import os, random
from itertools import product
import pytest
from rng_research.rng_properties import (chi_square_frequency, monobit,
                                         serial_correlation, poker_test,
                                         entropy_estimate, distinct_ratio,
                                         run_all_tests)

def uniform_stream(n=20000, seed=1234):
    rng = random.Random(seed)
    return [rng.randrange(256) for _ in range(n)]

def test_chi_square_passes_on_uniform():
    r = chi_square_frequency(uniform_stream())
    assert r.passed and r.p_value is not None and r.p_value > 0.01

def test_chi_square_fails_on_biased():
    data = [7] * 5000 + [random.randrange(256) for _ in range(500)]
    r = chi_square_frequency(data)
    assert not r.passed

def test_chi_square_rejects_out_of_range():
    with pytest.raises(ValueError):
        chi_square_frequency([256, 1])

def test_monobit_empty_raises():
    with pytest.raises(ValueError):
        monobit([])

def test_monobit_balanced_passes():
    # alternating bits => perfectly balanced
    data = [0b01010101] * 1000
    assert monobit(data).passed

def test_serial_correlation_detects_ramp():
    ramp = [i % 256 for i in range(4000)]
    r = serial_correlation(ramp, lag=1)
    assert not r.passed  # strong positive correlation

def test_serial_correlation_uniform_ok():
    assert serial_correlation(uniform_stream()).passed

def test_poker_runs_and_returns_pvalue():
    r = poker_test(uniform_stream())
    assert 0.0 <= (r.p_value or 0) <= 1.0

def test_entropy_near_8_for_uniform():
    h = entropy_estimate(uniform_stream(50000))
    assert h > 7.9

def test_entropy_zero_for_constant():
    assert entropy_estimate([3] * 100) == 0.0

def test_distinct_ratio():
    assert distinct_ratio([1, 2, 3, 4]) == 1.0
    assert distinct_ratio([1, 1, 1, 1]) == 0.25

def test_run_all_tests_shape():
    res = run_all_tests(uniform_stream())
    names = {t.name for t in res}
    assert {"chi_square_frequency", "monobit", "serial_correlation_lag1", "poker"} <= names

def test_os_csprng_stream_passes():
    # A true CSPRNG stream legitimately fails an alpha=0.01 battery ~4% of the
    # time (multiple-hypothesis effect), so a single unseeded sample would make
    # this test flaky.  Use a fixed-seed os.urandom substitute (random.Random)
    # for determinism, plus a gate over fresh samples that a *broken* suite
    # (e.g. an invalid poker statistic) would fail nearly every time.
    rng = random.Random(2023)
    deterministic_sample = [rng.randrange(256) for _ in range(20000)]
    assert all(t.passed for t in run_all_tests(deterministic_sample))

    failures = sum(
        1 for s in range(10)
        if not all(t.passed for t in run_all_tests(
            [x for x in random.Random(50_000 + s).randbytes(20000)]))
    )
    assert failures <= 1, f"{failures}/10 CSPRNG-model samples failed the battery"

    # Fresh-urandom sanity check, calibrated to the corrected df=3 poker test:
    # per-sample battery failure rate is ≈4%, so P(≥3 failures in 10) ≈ 1.2% —
    # a stable threshold under binomial sampling.  A broken battery (e.g. the
    # previous k-1 df bug, which rejected essentially every sample) trips it.
    urandom_failures = sum(
        1 for _ in range(10)
        if not all(t.passed for t in run_all_tests(list(os.urandom(20000))))
    )
    assert urandom_failures <= 2, (
        f"{urandom_failures}/10 CSPRNG samples failed the battery")

# --- regression tests for the poker_test AttributeError root cause -----------
# The old implementation called `vi.get(...)` on a *list* (AttributeError) and
# computed an invalid statistic.  These tests lock in the fixed behaviour.

def test_poker_low_entropy_stream_fails():
    """Only two distinct bytes => many repeated 4-nibble patterns => must fail."""
    data = [0, 1] * 5000
    r = poker_test(data)
    assert not r.passed
    assert r.p_value is not None and r.p_value < 0.01


def test_poker_rejects_out_of_range_bytes():
    with pytest.raises(ValueError):
        poker_test([256])


def test_poker_rejects_empty_data():
    with pytest.raises(ValueError):
        poker_test([])


def test_poker_rejects_bad_parameters():
    with pytest.raises(ValueError):
        poker_test([1, 2, 3], m=0)
    with pytest.raises(ValueError):
        poker_test([1, 2, 3], m=20, k=16)


# --- df / parameter-contract tests ------------------------------------------
# The classes counted by poker_test are "number of distinct nibbles per group"
# (j = 1..m), all with strictly positive probability, so the multinomial has m
# categories and the chi-square statistic carries df = m - 1 (= 3 for the
# default m = 4, k = 16), NOT k - 1 = 15.

def _stirling(n_: int, r_: int) -> int:
    dp = [[0] * (r_ + 1) for _ in range(n_ + 1)]
    dp[0][0] = 1
    for i in range(1, n_ + 1):
        for j in range(1, min(i, r_) + 1):
            dp[i][j] = j * dp[i - 1][j] + dp[i - 1][j - 1]
    return dp[n_][r_]


def _falling(nn: int, rr: int) -> int:
    out = 1
    for i in range(rr):
        out *= nn - i
    return out


def _groups_by_class(m: int, k: int, counts: list[int], seed: int):
    """Deterministically generate groups whose class histogram == `counts`."""
    rng = random.Random(seed)
    groups: list[tuple[int, ...]] = []
    for j in range(1, m + 1):
        made = 0
        while made < counts[j]:
            g = tuple(rng.randrange(k) for _ in range(m))
            if len(set(g)) == j:
                groups.append(g)
                made += 1
    return groups


def _to_payload(groups) -> list[int]:
    """Pack m-nibble groups into bytes so poker_test re-extracts them exactly.

    poker_test appends, per byte, the LOW nibble first and the HIGH nibble
    second (byte & 0xF, then byte >> 4), i.e. it reads nibbles in stream
    order.  Therefore consecutive pairs of the group must be packed as
    (even_index | odd_index << 4); no reversal is required anywhere else.
    """
    payload: list[int] = []
    for g in groups:
        for a, b in zip(g[0::2], g[1::2]):
            payload.append(a | (b << 4))
    return payload


def _exact_h0_groups(n_groups: int, m: int = 4, k: int = 16, seed: int = 42):
    """Deterministic group multiset whose class counts match H0 exactly.

    Returns (bytes_payload, class_counts).  With n_groups = k**m every expected
    class count E_j = n * S(m,j)*(k)_j / k**m is an integer, so the chi-square
    statistic is mathematically forced to 0 under the correct df = m-1 model.
    """
    counts = [0] * (m + 1)
    for j in range(1, m + 1):
        counts[j] = n_groups * _stirling(m, j) * _falling(k, j) // k ** m
    return _to_payload(_groups_by_class(m, k, counts, seed)), counts


def test_poker_df_is_m_minus_one_not_k_minus_one():
    """Exact-H0 stream => stat must be 0 and p ~ 1 under the df=m-1 model."""
    payload, counts = _exact_h0_groups(16 ** 4)
    assert counts[1:] == [16, 1680, 20160, 43680]  # analytic E_j, m=4, k=16
    r = poker_test(payload)
    assert r.statistic == pytest.approx(0.0, abs=1e-9)
    assert r.p_value is not None and r.p_value > 0.99
    assert r.passed
    # the reported contract must name the correct degrees of freedom
    assert "df=3" in r.threshold_note


def test_poker_df_reflects_m_in_threshold_note():
    """df advertised in the result must track m, not the alphabet size k.

    Uses m = 4 with n = 16**4 groups.  The class counts are the exact
    integers E_j = S(4,j)*(16)_j = {16, 1680, 20160, 43680}
    (sum = 65536 = 16**4), so a stream whose class histogram matches them
    forces stat == 0 mathematically under the df = m-1 = 3 model — the old
    k-1 code would have reported df = 15 in threshold_note.

    Construction note: for m = 4, k = 16 every expected class count equals
    the number of *distinct* tuples of that class, so each distinct tuple
    is used exactly once (no rejection sampling, no pool exhaustion).
    _to_payload packs nibbles in stream order, which poker_test re-extracts
    unchanged, so each group's class is preserved bit-for-bit.
    """
    def _groups_exact(m: int, k: int, counts: list[int]):
        """Exhaustively enumerate ALL k**m tuples of a given class."""
        all_tuples = [tuple(t) for t in product(range(k), repeat=m)]
        groups: list[tuple[int, ...]] = []
        for j in range(1, m + 1):
            pool = [t for t in all_tuples if len(set(t)) == j]
            assert len(pool) == counts[j], (
                f"class {j}: expected {counts[j]} groups but {len(pool)} "
                "distinct tuples exist; pick feasible expected counts")
            groups.extend(pool)
        return groups

    # Exact H0 expectation for m=4, k=16: P(j)=S(4,j)(16)_j/16^4 => E_j =
    # S(4,j)*(16)_j, all integers and all <= available distinct tuples.
    counts = [0, 16, 1680, 20160, 43680]
    assert sum(counts) == 16 ** 4
    payload = _to_payload(_groups_exact(4, 16, counts))
    assert len(payload) == 2 * sum(counts[1:])  # 4 nibbles packed per 2 bytes
    r = poker_test(payload, m=4)
    assert "df=3" in r.threshold_note
    assert r.statistic == pytest.approx(0.0, abs=1e-9)
    assert r.passed


def test_poker_critical_boundary_follows_df3_model():
    """Statistics between the df=3 and df=15 alpha=0.01 critical values
    (11.3449 .. 30.5778) must FAIL under the correct df=3 model; they would
    wrongly pass if the code still used df=15.  The moved-group construction
    makes the statistic analytically known in advance — no arbitrary bound.
    """
    n = 16 ** 4
    e = {j: n * _stirling(4, j) * _falling(16, j) / n for j in range(1, 5)}
    coef = 1.0 / e[1] + 1.0 / e[4]  # stat = d^2 * coef when d groups move 4->1
    base_counts = [0, 16, 1680, 20160, 43680]

    for target in (12.0, 20.0):
        d = round(math.sqrt(target / coef))
        counts = list(base_counts)
        counts[4] -= d
        counts[1] += d
        payload = _to_payload(_groups_by_class(4, 16, counts, seed=42))
        r = poker_test(payload)
        assert r.statistic == pytest.approx(d * d * coef, rel=1e-6)
        assert 11.3449 < r.statistic < 30.5778
        assert not r.passed, (
            f"stat={r.statistic:.3f} must fail under df=3 (crit 11.3449); "
            "passing here would indicate the wrong df=15 model")
        assert r.p_value is not None and r.p_value < 0.01


def test_poker_rejects_degenerate_m_one():
    """m=1 gives zero degrees of freedom — must raise, never divide by df=0."""
    with pytest.raises(ValueError):
        poker_test(uniform_stream(100), m=1)


def test_poker_rejects_alphabet_mismatch_k():
    """k != 16 contradicts the real nibble alphabet (0..15) — reject loudly."""
    with pytest.raises(ValueError):
        poker_test(uniform_stream(100), k=8)
    with pytest.raises(ValueError):
        poker_test(uniform_stream(100), k=256)


def test_poker_pvalue_matches_exact_chi_square_df3():
    """The Wilson–Hilferty tail used internally must agree with the exact
    chi-square(df=3) survival function at representative statistics, and the
    exact critical value 11.3449 must map to p ≈ 0.01."""
    def chi2_sf(x: float, df: int) -> float:
        a = df / 2.0
        xx = x / 2.0
        if xx == 0:
            return 1.0
        if xx < a + 1:  # series for regularized P(a,x)
            ap, s, delta = a, 1.0 / a, 1.0 / a
            for n in range(1, 500):
                ap += 1
                delta *= xx / ap
                s += delta
                if abs(delta) < abs(s) * 1e-15:
                    break
            p = s * math.exp(-xx + a * math.log(xx) - math.lgamma(a))
            return 1.0 - p
        tiny = 1e-300  # continued fraction for Q(a,x)
        b = xx + 1 - a
        c, d = 1 / tiny, 1 / b
        h = d
        for i in range(1, 500):
            an = -i * (i - a)
            b += 2
            d = an * d + b
            if abs(d) < tiny:
                d = tiny
            c = b + an / c
            if abs(c) < tiny:
                c = tiny
            d = 1 / d
            de = d * c
            h *= de
            if abs(de - 1) < 1e-15:
                break
        return math.exp(-xx + a * math.log(xx) - math.lgamma(a)) * h

    df = 3
    for stat in (5.0, 11.3449, 20.0):
        z = ((stat / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
        wh = 1 - 0.5 * math.erfc(-z / math.sqrt(2))
        exact = chi2_sf(stat, df)
        assert abs(wh - exact) < 0.002, f"stat={stat}: WH={wh:.5f} exact={exact:.5f}"
    # the critical value itself maps to p ≈ 0.01 under the df=3 model
    assert abs(chi2_sf(11.3449, df) - 0.01) < 1e-4


def test_poker_statistic_matches_known_uniform_expectation():
    """For a uniform stream the poker statistic should be O(df)=O(3), not huge."""
    r = poker_test(uniform_stream(20000, seed=99))
    assert 0.0 <= r.statistic < 30.0
