from pathlib import Path
import pytest
from rng_research.source_analysis import (analyze_source_file, classify_snapshot,
                                          SourceAnalysisError)

ROOT = Path(__file__).resolve().parents[1]
VULN = ROOT / "fixtures/source-snapshots/Random.cpp@69b2da9826df.txt"
FIXED = ROOT / "fixtures/source-snapshots/Random.cpp@d3c2eee16b15.txt"

def test_vulnerable_snapshot_classification():
    r = analyze_source_file(VULN)
    assert r.uses_mt19937 and r.reseeds_per_call and r.seeds_with_random_device
    assert not r.delegates_to_js_crypto
    assert classify_snapshot(r) == "vulnerable"
    assert r.sha256 == "f8dea1b9bd1e7057a0f7166ef372e3b34fc4a96eb7fa9e31bbd137beb8c5aab1"

def test_fixed_snapshot_classification():
    r = analyze_source_file(FIXED)
    assert r.delegates_to_js_crypto and not r.uses_mt19937
    assert classify_snapshot(r) == "fixed"
    assert r.sha256 == "609bb7543f9d0d1200f7e62c69c428e805b5e2b4600ece2e60656216ae7f096f"

def test_findings_have_line_numbers():
    r = analyze_source_file(VULN)
    assert all(f.line >= 1 for f in r.findings)
    assert any(f.name == "mt19937" for f in r.findings)

def test_comments_ignored(tmp_path):
    p = tmp_path / "c.txt"; p.write_text("// std::mt19937 in a comment\nint x;\n")
    r = analyze_source_file(p)
    assert not r.uses_mt19937
    assert classify_snapshot(r) == "unknown"

def test_missing_file_raises():
    with pytest.raises(SourceAnalysisError):
        analyze_source_file("/nonexistent/Random.cpp")

def test_directory_raises():
    with pytest.raises(SourceAnalysisError):
        analyze_source_file(ROOT / "fixtures")

def test_empty_file_raises(tmp_path):
    p = tmp_path / "e.txt"; p.write_text("")
    with pytest.raises(SourceAnalysisError):
        analyze_source_file(p)

def test_binary_raises(tmp_path):
    p = tmp_path / "b.bin"; p.write_bytes(b"\xff\xfe\x00\x01garbage\xff")
    with pytest.raises(SourceAnalysisError):
        analyze_source_file(p)

def test_synthetic_fixture_is_analyzed(tmp_path):
    # synthetic file clearly labelled as model input
    src = '''#include <cstdint>
#include <emscripten.h>
extern "C" {
uint32_t random32(void) { EM_ASM_INT_V({ return Module.getRandomValue(); }); }
void f(){ crypto_.getRandomValues(buf); }
}
'''
    p = tmp_path / "synth.txt"; p.write_text(src)
    r = analyze_source_file(p)
    assert r.delegates_to_js_crypto
