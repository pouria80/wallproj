import json
from pathlib import Path
import pytest
from rng_research.evidence import load_ledger
from rng_research.experiment_runner import run_experiment
from rng_research.report_generator import (build_report_payload, write_json_report,
                                           write_markdown_report)

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture()
def payload():
    recs = load_ledger(ROOT / "config/evidence_ledger.json")
    runs = [run_experiment("E1-source-snapshot-analysis"),
            run_experiment("E4-secure-rng-properties", {"samples": 1000})]
    return build_report_payload(recs, runs)

def test_payload_structure(payload):
    assert payload["tool"] == "rng_research"
    assert payload["evidence_summary"]["total"] >= 8
    assert len(payload["experiments"]) == 2
    assert "separation_note" in payload

def test_json_report_written(tmp_path, payload):
    p = write_json_report(payload, tmp_path / "sub/report.json")
    assert p.exists()
    d = json.loads(p.read_text(encoding="utf-8"))
    assert d["tool_version"] == payload["tool_version"]

def test_markdown_report_content(tmp_path, payload):
    p = write_markdown_report(payload, tmp_path / "r.md")
    text = p.read_text(encoding="utf-8")
    assert "دفتر شواهد" in text
    assert "E1-source-snapshot-analysis" in text
    assert "محدودیت" in text  # limitations rendered
    assert "گزارش تحقیق" in text

def test_markdown_includes_run_ids(tmp_path, payload):
    p = write_markdown_report(payload, tmp_path / "r2.md")
    text = p.read_text(encoding="utf-8")
    for run in payload["experiments"]:
        assert run["run_id"] in text
