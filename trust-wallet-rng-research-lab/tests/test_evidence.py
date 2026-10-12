import json
from pathlib import Path
import pytest
from rng_research.evidence import (load_ledger, save_ledger, validate_ledger,
                                   add_record, render_markdown_table, summarize,
                                   EvidenceLedgerError)
from rng_research.models import EvidenceRecord

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "config" / "evidence_ledger.json"

def make_rec(**kw):
    base = dict(claim="c", source="s", locator="l", method="m", status="confirmed")
    base.update(kw); return EvidenceRecord(**base)

def test_load_real_ledger():
    recs = load_ledger(LEDGER)
    assert len(recs) >= 8
    assert all(r.validate() == [] for r in recs)

def test_validate_flags_bad_status(tmp_path):
    bad = make_rec(status="definitely_true")
    errs = validate_ledger([bad])
    assert any("status" in e for e in errs)

def test_validate_flags_empty_claim():
    assert make_rec(claim="  ").validate()

def test_duplicate_claims_flagged():
    errs = validate_ledger([make_rec(claim="X"), make_rec(claim="x")])
    assert any("duplicate" in e for e in errs)

def test_add_record_validates():
    with pytest.raises(EvidenceLedgerError):
        add_record([], make_rec(confidence="extreme"))

def test_save_roundtrip(tmp_path):
    p = tmp_path / "led.json"
    recs = [make_rec(claim="one"), make_rec(claim="two", status="refuted")]
    save_ledger(recs, p)
    loaded = load_ledger(p)
    assert [r.claim for r in loaded] == ["one", "two"]
    assert loaded[1].status == "refuted"

def test_missing_file(tmp_path):
    with pytest.raises(EvidenceLedgerError):
        load_ledger(tmp_path / "nope.json")

def test_malformed_json(tmp_path):
    p = tmp_path / "bad.json"; p.write_text("{not json")
    with pytest.raises(EvidenceLedgerError):
        load_ledger(p)

def test_wrong_shape(tmp_path):
    p = tmp_path / "shape.json"; p.write_text(json.dumps({"records": {"a": 1}}))
    with pytest.raises(EvidenceLedgerError):
        load_ledger(p)

def test_record_missing_field(tmp_path):
    p = tmp_path / "miss.json"; p.write_text(json.dumps({"records": [{"claim": "x"}]}))
    with pytest.raises(EvidenceLedgerError) as ei:
        load_ledger(p)
    assert "missing fields" in str(ei.value)

def test_markdown_table_contains_headers_and_fa_status():
    table = render_markdown_table([make_rec(status="confirmed")])
    assert "ادعا" in table and "وضعیت" in table
    assert "تأییدشده" in table

def test_summarize_counts():
    s = summarize([make_rec(), make_rec(claim="b", status="refuted")])
    assert s["total"] == 2 and s["by_status"]["confirmed"] == 1
