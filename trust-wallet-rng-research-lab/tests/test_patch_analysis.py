from pathlib import Path
import pytest
from rng_research.patch_analysis import compare_files, verify_patch_file, PatchError

ROOT = Path(__file__).resolve().parents[1]
VULN = ROOT / "fixtures/source-snapshots/Random.cpp@69b2da9826df.txt"
FIXED = ROOT / "fixtures/source-snapshots/Random.cpp@d3c2eee16b15.txt"
PATCH = ROOT / "fixtures/patches/d3c2eee16b15.diff"

def test_identical_files():
    c = compare_files(VULN, VULN)
    assert c.stats.identical and c.stats.added == 0 and c.stats.removed == 0
    assert c.unified_diff == ""

def test_different_files_stats():
    c = compare_files(VULN, FIXED)
    assert not c.stats.identical
    assert c.stats.added > 40 and c.stats.removed >= 4
    assert "mt19937" in c.unified_diff

def test_semantic_key_changes_detected():
    c = compare_files(VULN, FIXED)
    joined = " ".join(c.key_changes).lower()
    assert "random_device" in joined or "mt19937" in joined
    assert "getrandomvalues" in joined
    assert "fail-closed" in joined or "no secure" in joined

def test_missing_file_raises(tmp_path):
    with pytest.raises(PatchError):
        compare_files(tmp_path / "nope", VULN)

def test_stored_patch_matches_snapshots():
    assert verify_patch_file(PATCH, VULN, FIXED)

def test_tampered_patch_fails(tmp_path):
    tampered = tmp_path / "t.diff"
    tampered.write_text(PATCH.read_text().replace("+", "-", 3))
    assert not verify_patch_file(tampered, VULN, FIXED)

def test_non_utf8_raises(tmp_path):
    p = tmp_path / "bin"; p.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(PatchError):
        compare_files(p, VULN)
