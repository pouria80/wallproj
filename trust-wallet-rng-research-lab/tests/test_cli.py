import json, sys
from pathlib import Path
import pytest
from rng_research.cli import main

ROOT = Path(__file__).resolve().parents[1]

def run_cli(*argv):
    return main(list(argv))

def test_info_ok():
    assert run_cli("info") == 0

def test_check_environment_ok():
    assert run_cli("check-environment") == 0

def test_analyze_source_default_vuln(capsys):
    rc = run_cli("analyze-source", str(ROOT/"fixtures/source-snapshots/Random.cpp@69b2da9826df.txt"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "vulnerable" in out and "sha256" in out

def test_analyze_source_missing_file_returns_2(capsys):
    rc = run_cli("analyze-source", "/no/such/file.txt")
    assert rc == 2
    assert "error" in capsys.readouterr().out.lower()

def test_compare_defaults_and_fixture_integrity(capsys):
    rc = run_cli("compare")
    assert rc == 0
    out = capsys.readouterr().out
    assert "matches recomputed diff: True" in out

def test_compare_custom_files(tmp_path, capsys):
    a = tmp_path/"a.txt"; b = tmp_path/"b.txt"
    a.write_text("x\n"); b.write_text("y\n")
    assert run_cli("compare", str(a), str(b)) == 0

def test_compare_missing_returns_2():
    assert run_cli("compare", "/no/a", "/no/b") == 2

def test_evidence_validate(capsys):
    assert run_cli("evidence", "validate") == 0
    assert "ledger OK" in capsys.readouterr().out

def test_evidence_list_and_table(capsys):
    assert run_cli("evidence", "list") == 0
    assert run_cli("evidence", "table") == 0
    assert "ادعا" in capsys.readouterr().out

def test_evidence_add_then_bad_status(tmp_path):
    led = tmp_path/"led.json"
    led.write_text(json.dumps({"records": []}))
    rc = run_cli("evidence", "add", "--ledger", str(led), "--claim", "c1",
                 "--source", "s", "--locator", "l", "--method", "m",
                 "--status", "confirmed")
    assert rc == 0
    rc2 = run_cli("evidence", "add", "--ledger", str(led), "--claim", "c2",
                  "--source", "s", "--locator", "l", "--method", "m",
                  "--status", "bogus")
    assert rc2 == 2

def test_run_experiments_single(tmp_path, capsys):
    rc = run_cli("run-experiments", "--experiment", "E4-secure-rng-properties",
                 "--params", '{"samples": 1000}', "--out", str(tmp_path))
    assert rc == 0
    assert len(list(tmp_path.glob("*.json"))) == 1

def test_run_experiments_bad_params_json(tmp_path):
    assert run_cli("run-experiments", "--experiment", "E4-secure-rng-properties",
                   "--params", "{not json}", "--out", str(tmp_path)) == 2

def test_run_experiments_unknown_id(tmp_path):
    assert run_cli("run-experiments", "--experiment", "NOPE", "--out", str(tmp_path)) == 2

def test_report_generation(tmp_path):
    art = tmp_path/"art"
    assert run_cli("run-experiments", "--experiment", "E1-source-snapshot-analysis",
                   "--out", str(art)) == 0
    rc = run_cli("report", "--artifacts", str(art), "--out", str(tmp_path/"rep"))
    assert rc == 0
    assert (tmp_path/"rep"/"report.md").exists()
    d = json.loads((tmp_path/"rep"/"report.json").read_text(encoding="utf-8"))
    assert len(d["experiments"]) == 1

def test_no_command_errors():
    with pytest.raises(SystemExit):
        run_cli()
