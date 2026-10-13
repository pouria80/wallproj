"""U2: conformance of the independent MT19937 reference against an EXTERNAL oracle.

Oracle provenance is recorded in fixtures/references/mt19937_scalar_vectors.txt
and src/rng_research/mt19937_reference.py (module docstring).  These tests are
INDEPENDENT of CPython's random module — they compare against libstdc++ output.
"""
from pathlib import Path

import pytest

from rng_research.mt19937_reference import (MT19937Reference, load_scalar_vectors,
                                             temper)

REF_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "references"


@pytest.fixture(scope="module")
def vectors():
    return load_scalar_vectors(REF_DIR / "mt19937_scalar_vectors.txt")


def test_vector_file_present_and_wellformed(vectors):
    assert len(vectors) == 6
    for s, stream in vectors.items():
        assert 0 <= s < 2**32
        assert len(stream) == 5
        assert all(0 <= w < 2**32 for w in stream)


def test_reference_matches_external_oracle(vectors):
    """Bit-level match of seed->output streams vs libstdc++ std::mt19937."""
    m = MT19937Reference()
    for seed, expected in vectors.items():
        m.seed_scalar(seed)
        got = [m.next_uint32() for _ in range(len(expected))]
        assert got == list(expected), f"seed {seed}: {got} != {list(expected)}"


def test_first_output_after_seed_helper(vectors):
    m = MT19937Reference()
    for seed, expected in vectors.items():
        assert m.first_output_after_seed(seed) == expected[0]


def test_temper_is_bijection_on_uint32():
    """temper must be invertible over the uint32 domain (sampled proof)."""
    seen = set()
    step = 4093  # coprime-ish stride; covers many values quickly
    vals = [(i * step + (i >> 8)) & 0xFFFFFFFF for i in range(20000)]
    for y in vals:
        t = temper(y)
        assert 0 <= t < 2**32
        seen.add(t)
    assert len(seen) == len(vals), "temper collided on distinct inputs -> not a bijection"


def test_temper_one_value():
    # Documented value from the standard parameter set.
    assert temper(1) == 4194449


def test_cpython_seeding_contract_differs_from_libstdcxx(vectors):
    """Regression guard for the U2 finding: same uint32 seed, different engine.

    This asserts the DIFFERENCE explicitly so nobody 'fixes' the model by
    silently swapping engines.  The vulnerable historical build used
    libstdc++ init_genrand; CPython seeds via its own array-style path.
    """
    import random
    r = random.Random()
    diffs = 0
    for seed, expected in vectors.items():
        r.seed(seed, version=2)
        cp = [r.getrandbits(32) for _ in range(5)]
        if cp != list(expected):
            diffs += 1
    assert diffs == len(vectors), (
        "CPython and libstdc++ seeding unexpectedly converged; re-examine the "
        "seeding-contract analysis in docs/rng-conformance.md before trusting it")


def test_seed_scalar_input_validation():
    m = MT19937Reference()
    with pytest.raises(TypeError):
        m.seed_scalar(True)
    with pytest.raises(TypeError):
        m.seed_scalar("5489")
    m.seed_scalar(2**32 + 5489)  # documented mod-2^32 reduction
    m2 = MT19937Reference(); m2.seed_scalar(5489)
    assert m.mt == m2.mt


def test_seed_array_requires_nonempty_key():
    m = MT19937Reference()
    with pytest.raises(ValueError):
        m.seed_array([])


def test_stream_deterministic_across_twist_boundary():
    m = MT19937Reference(); m.seed_scalar(12345)
    a = [m.next_uint32() for _ in range(625)]
    m.seed_scalar(12345)
    b = [m.next_uint32() for _ in range(625)]
    assert a == b
