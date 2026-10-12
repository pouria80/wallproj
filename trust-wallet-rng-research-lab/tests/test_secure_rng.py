import pytest
from rng_research.secure_rng import (secure_bytes, model_random32,
                                     model_random_buffer_seeded,
                                     model_per_call_reseed_sequence,
                                     model_effective_state_space, SecureRNGError)

def test_secure_bytes_length_and_uniqueness():
    a, b = secure_bytes(32), secure_bytes(32)
    assert len(a) == 32 and a != b

def test_secure_bytes_validation():
    for bad in (0, -1, True, "x", 10_000_001):
        with pytest.raises(SecureRNGError):
            secure_bytes(bad)

def test_model_random32_deterministic_and_uint32():
    x = model_random32(42)
    assert x == model_random32(42)
    assert 0 <= x < 2**32

def test_model_random32_seed_range_validation():
    for bad in (-1, 2**32):
        with pytest.raises(ValueError):
            model_random32(bad)

def test_model_buffer_determinism():
    assert (model_random_buffer_seeded(7, 16) ==
            model_random_buffer_seeded(7, 16))
    assert len(model_random_buffer_seeded(7, 16)) == 16

def test_model_buffer_different_seeds_differ():
    assert model_random_buffer_seeded(1, 16) != model_random_buffer_seeded(2, 16)

def test_model_buffer_length_validation():
    with pytest.raises(ValueError):
        model_random_buffer_seeded(1, 0)

def test_per_call_reseed_sequence_identical_for_same_seed():
    bufs = model_per_call_reseed_sequence([5, 5, 9], buffer_len=8)
    assert bufs[0] == bufs[1] and bufs[0] != bufs[2]

def test_state_space_collapse_demo():
    seeds = list(range(2000))
    stats = model_effective_state_space(seeds, buffer_len=16)
    assert stats["unique_seeds"] == 2000
    assert stats["distinct_buffers"] == 2000  # injective over small samples
    assert stats["theoretical_max_distinct_from_32bit_seeds"] == 2**32

def test_state_space_duplicate_seeds_counted():
    stats = model_effective_state_space([1, 1, 1, 2], buffer_len=4)
    assert stats["duplicate_seed_draws"] == 2
    assert stats["distinct_buffers"] == 2
