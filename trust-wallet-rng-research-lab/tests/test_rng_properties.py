import os, random
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
        1 for _ in range(10)
        if not all(t.passed for t in run_all_tests(list(os.urandom(20000))))
    )
    assert failures <= 1, f"{failures}/10 CSPRNG samples failed the battery"

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


def test_poker_statistic_matches_known_uniform_expectation():
    """For a uniform stream the poker statistic should be O(df)=O(15), not huge."""
    r = poker_test(uniform_stream(20000, seed=99))
    assert 0.0 <= r.statistic < 100.0
