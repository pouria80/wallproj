import json
import shutil
from pathlib import Path
import pytest
from rng_research.experiment_runner import (run_experiment, run_suite,
                                            list_experiments, ExperimentError)

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "config/experiments.json"

def test_list_experiments_all_three_categories():
    exps = list_experiments()
    cats = {v["category"] for v in exps.values()}
    assert {"real-evidence", "modelling", "security-fix"} <= cats
    assert len(exps) >= 5

def test_unknown_experiment_raises():
    with pytest.raises(ExperimentError):
        run_experiment("E99-does-not-exist")

def test_e1_real_evidence_run():
    run = run_experiment("E1-source-snapshot-analysis")
    assert run.category == "real-evidence"
    assert run.results["sha_matches_upstream_record"] is True
    assert run.results["vulnerable_snapshot"]["classification"] == "vulnerable"
    assert run.results["fixed_snapshot"]["classification"] == "fixed"
    assert run.limitations

def test_e2_modelling_run():
    run = run_experiment("E2-modelling-seed-collapse", {"draws": 500, "buffer_len": 8})
    assert run.results["unique_seeds"] <= 500
    assert run.results["same_seed_same_output"] is True

def test_e2_param_validation():
    with pytest.raises(ExperimentError):
        run_experiment("E2-modelling-seed-collapse", {"draws": 0})

def test_e3_stats_deception_run():
    run = run_experiment("E3-modelling-stats-deception", {"bytes": 4000})
    assert run.results["effective_key_entropy_bits"] == 32
    assert run.results["stream_length"] == 4000

def test_e4_secure_rng_run():
    run = run_experiment("E4-secure-rng-properties", {"samples": 5000})
    assert run.results["two_draws_differ"] is True
    assert run.results["shannon_entropy_bits_per_byte"] > 7.5

def test_run_metadata_fields():
    run = run_experiment("E4-secure-rng-properties", {"samples": 1000})
    d = run.to_dict()
    for k in ("run_id", "started_at", "finished_at", "tool_version", "python_version"):
        assert d[k]

def test_run_suite_writes_artifacts(tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"experiments": {
        "E1-source-snapshot-analysis": {"enabled": True, "params": {}},
        "E4-secure-rng-properties": {"enabled": True, "params": {"samples": 1000}},
        "E3-modelling-stats-deception": {"enabled": False}}}))
    out = tmp_path / "art"
    runs = run_suite(cfg, out)
    assert len(runs) == 2  # disabled one skipped entirely
    files = sorted(out.glob("*.json"))
    assert len(files) == 2
    loaded = json.loads(files[0].read_text())
    assert "run_id" in loaded and "results" in loaded

def test_run_suite_records_skip_reason(tmp_path, monkeypatch):
    """Platform-independent: production code resolves node via shutil.which.

    Case 1 (node unavailable): PATH is emptied so shutil.which("node")
    returns None on every OS -> the run must be recorded as skipped with a
    human-readable reason.  Case 2 (node available) is covered by
    test_run_suite_node_available_when_present below.
    """
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"experiments": {
        "E5-node-bridge-check": {"enabled": True, "params": {"out": str(tmp_path/"x.js")}}}}))
    # Empty PATH -> shutil.which("node") finds nothing on Windows/Linux/macOS.
    monkeypatch.setenv("PATH", str(tmp_path))
    runs = run_suite(cfg, tmp_path / "art")
    r = runs[0]
    assert r.results.get("skipped") is True
    reason = r.results.get("reason", "")
    assert "node" in reason.lower()


@pytest.mark.skipif(shutil.which("node") is None, reason="node executable not present")
def test_run_suite_node_available_when_present(tmp_path):
    """When node IS resolvable via shutil.which, E5 must actually run the
    bridge (no skip).  Skipped automatically on machines without Node."""
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"experiments": {
        "E5-node-bridge-check": {"enabled": True, "params": {"out": str(tmp_path/"x.js")}}}}))
    runs = run_suite(cfg, tmp_path / "art")
    r = runs[0]
    assert r.results.get("skipped") is not True
    assert r.results.get("bridge_ran") is True

def test_run_suite_missing_config(tmp_path):
    with pytest.raises(ExperimentError):
        run_suite(tmp_path / "nope.json", tmp_path / "out")

def test_run_suite_bad_shape(tmp_path):
    cfg = tmp_path / "c.json"; cfg.write_text('{"experiments": []}')
    with pytest.raises(ExperimentError):
        run_suite(cfg, tmp_path / "out")
