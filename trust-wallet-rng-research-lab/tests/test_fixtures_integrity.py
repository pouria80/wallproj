"""Integrity tests for REAL upstream fixtures (separate from synthetic ones)."""
import hashlib, json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SNAPS = ROOT / "fixtures/source-snapshots"

EXPECTED = {
    "Random.cpp@69b2da9826df.txt": "f8dea1b9bd1e7057a0f7166ef372e3b34fc4a96eb7fa9e31bbd137beb8c5aab1",
    "Random.cpp@d3c2eee16b15.txt": "609bb7543f9d0d1200f7e62c69c428e805b5e2b4600ece2e60656216ae7f096f",
}

@pytest.mark.parametrize("name,digest", EXPECTED.items())
def test_snapshot_hash_matches_provenance(name, digest):
    data = (SNAPS/name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest

def test_provenance_json_consistent():
    prov = json.loads((SNAPS/"provenance.json").read_text())
    for s in prov["snapshots"]:
        p = SNAPS/s["local_file"]
        assert p.exists()
        assert hashlib.sha256(p.read_bytes()).hexdigest() == s["sha256"]

def test_advisory_fixture_has_cve_id():
    adv = json.loads((SNAPS/"GHSA-pm4f-pggw-8jwc.json").read_text())
    assert adv["cve_id"] == "CVE-2023-31290"
    assert "mt19937" in adv["description"] or "32-bit" in adv["description"]

def test_commit_fixture_metadata():
    cm = json.loads((SNAPS/"commit-d3c2eee16b15.json").read_text())
    assert cm["sha"].startswith("d3c2eee")
    assert cm["parents"][0].startswith("69b2da9")
    assert [f["filename"] for f in cm["files"]] == ["wasm/src/Random.cpp"]

def test_synthetic_dir_labelled():
    marker = ROOT/"fixtures/synthetic/README.md"
    assert marker.exists()
    assert "synthetic" in marker.read_text().lower()
