"""Tests for the deterministic seed→mnemonic reconstruction engine.

All mnemonics/seeds used here are SYNTHETIC (generated inside the tests from
declared seeds) — no real wallets, no network access.
"""
from __future__ import annotations

import pytest

from rng_research import mnemonic_recovery as mr
from rng_research.mt19937_reference import MT19937Reference, load_scalar_vectors


# ---------------------------------------------------------------------------
# BIP-39 layer
# ---------------------------------------------------------------------------

def test_builtin_bip39_matches_official_vectors():
    vectors = mr.load_bip39_vectors()
    assert len(vectors) >= 4
    for hexent, expected in vectors:
        assert mr.entropy_to_mnemonic_ref(bytes.fromhex(hexent)) == expected
        assert mr.mnemonic_to_entropy_ref(expected).hex() == hexent


def test_provider_detected_and_vector_verified():
    prov = mr.get_provider()
    assert prov.name in ("python-mnemonic", "builtin-reference")
    assert prov.vectors_verified is True


def test_wordlist_integrity():
    wl = mr.builtin_wordlist()
    assert len(wl) == 2048
    assert wl[0] == "abandon" and wl[-1] == "zoo"


def test_checksum_rejection():
    bad = "abandon " * 11 + "zoo"  # wrong checksum word
    with pytest.raises(mr.RecoveryError):
        mr.mnemonic_to_entropy_ref(bad)


def test_invalid_entropy_length_rejected():
    with pytest.raises(mr.RecoveryError):
        mr.entropy_to_mnemonic_ref(b"\x00" * 15)


def test_seed_derivation_deterministic():
    ent = bytes(range(16))
    m = mr.entropy_to_mnemonic_ref(ent)
    s1 = mr.mnemonic_to_seed_ref(m)
    s2 = mr.mnemonic_to_seed_ref(m, passphrase="test")
    assert len(s1) == 64 and s1 != s2


# ---------------------------------------------------------------------------
# Vulnerable-stream reconstruction (must use the ORACLE-VERIFIED core)
# ---------------------------------------------------------------------------

def test_vulnerable_buffer_uses_libstdcxx_convention_not_cpython():
    """Cross-check against the external oracle vectors directly."""
    vecs = load_scalar_vectors("fixtures/references/mt19937_scalar_vectors.txt")
    seed = next(iter(vecs))
    first_words = vecs[seed][0]
    buf = mr.vulnerable_random_buffer(seed, 4)
    assert buf[0] == first_words & 0xFF  # low byte of FIRST output


def test_vulnerable_buffer_deterministic_and_bounds():
    a = mr.vulnerable_random_buffer(0x12345678, 16)
    b = mr.vulnerable_random_buffer(0x12345678, 16)
    assert a == b and len(a) == 16
    with pytest.raises(mr.RecoveryError):
        mr.vulnerable_random_buffer(-1)
    with pytest.raises(mr.RecoveryError):
        mr.vulnerable_random_buffer(1, 0)
    with pytest.raises(mr.RecoveryError):
        mr.vulnerable_random_buffer(2**32, 16)


def test_differs_from_cpython_model():
    """The verified libstdc++ stream must NOT equal the old CPython-convention
    model — this documents why the new engine replaces it for exact work."""
    from rng_research.secure_rng import model_random_buffer_seeded
    diffs = sum(1 for s in range(50)
                if model_random_buffer_seeded(s, 16) != mr.vulnerable_random_buffer(s, 16))
    assert diffs == 50  # every seed diverges (seeding contract differs)


# ---------------------------------------------------------------------------
# Recovery / audit workflows
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def synthetic_case():
    seed = 0x0BADF00D
    buf = mr.vulnerable_random_buffer(seed, 16)
    return seed, buf.hex(), mr.entropy_to_mnemonic_ref(buf)


def test_targeted_audit_finds_own_seed(synthetic_case):
    seed, _, mnemonic = synthetic_case
    rep = mr.recover_seeds_for_mnemonic(mnemonic, known_seeds=[1, 2, seed, 3])
    assert rep["match_found"] and rep["mode"] == "targeted-audit"
    assert [m["seed"] for m in rep["matches"]] == [seed]


def test_targeted_audit_negative(synthetic_case):
    seed, _, mnemonic = synthetic_case
    others = [s for s in (seed - 1, seed + 1) if 0 <= s < 2**32]
    rep = mr.recover_seeds_for_mnemonic(mnemonic, known_seeds=others)
    assert not rep["match_found"]


def test_bounded_scan_finds_seed_in_window(synthetic_case):
    seed, _, mnemonic = synthetic_case
    base = seed & 0xFFFFFF00
    rep = mr.recover_seeds_for_mnemonic(mnemonic, start=base, end=base + 255)
    assert rep["match_found"]
    assert any(m["seed"] == seed for m in rep["matches"])


def test_scope_cap_blocks_large_sweeps():
    with pytest.raises(mr.RecoveryError, match="scope cap"):
        mr.seed_range(0, 2**32 - 1)
    with pytest.raises(mr.RecoveryError):
        mr.seed_range(0, mr.MAX_ENUMERATION_SEEDS)  # exactly cap+1


def test_enumerate_window_capped():
    rows = mr.enumerate_window_seeds(0, 3)
    assert len(rows) == 3
    assert all(len(r["mnemonic"].split()) == 12 for r in rows)
    with pytest.raises(mr.RecoveryError):
        mr.enumerate_window_seeds(0, mr.MAX_ENUMERATION_SEEDS + 1)


def test_bad_mnemonic_raises(synthetic_case):
    with pytest.raises(mr.RecoveryError):
        mr.recover_seeds_for_mnemonic("not a valid mnemonic at all here ok",
                                      known_seeds=[1])


def test_entropy_len_mismatch_raises(synthetic_case):
    _, _, mnemonic = synthetic_case
    with pytest.raises(mr.RecoveryError, match="entropy"):
        mr.recover_seeds_for_mnemonic(mnemonic, known_seeds=[1], entropy_len=32)
