"""Evidence ledger: load, validate, store and render evidence records.

The ledger lives in `config/evidence_ledger.json` (source of truth) and can be
exported to Markdown tables for documentation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import EvidenceRecord


class EvidenceLedgerError(Exception):
    """Raised when the ledger file is missing or malformed."""


def load_ledger(path: str | Path) -> list[EvidenceRecord]:
    p = Path(path)
    if not p.exists():
        raise EvidenceLedgerError(f"ledger file not found: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise EvidenceLedgerError(f"ledger file is not valid JSON: {p}: {e}") from e
    if not isinstance(raw, dict) or "records" not in raw:
        raise EvidenceLedgerError("ledger JSON must be an object with a 'records' list")
    records_raw = raw["records"]
    if not isinstance(records_raw, list):
        raise EvidenceLedgerError("'records' must be a list")
    records: list[EvidenceRecord] = []
    for i, item in enumerate(records_raw):
        if not isinstance(item, dict):
            raise EvidenceLedgerError(f"record #{i} is not an object")
        try:
            records.append(EvidenceRecord.from_dict(item))
        except ValueError as e:
            raise EvidenceLedgerError(f"record #{i}: {e}") from e
    return records


def save_ledger(records: list[EvidenceRecord], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"records": [r.to_dict() for r in records]}
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                 encoding="utf-8")


def validate_ledger(records: list[EvidenceRecord]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for i, r in enumerate(records):
        for err in r.validate():
            errors.append(f"record #{i} ({r.claim[:40]!r}): {err}")
        key = r.claim.strip().lower()
        if key in seen:
            errors.append(f"record #{i}: duplicate claim {r.claim[:40]!r}")
        seen.add(key)
    return errors


def add_record(records: list[EvidenceRecord], record: EvidenceRecord) -> list[EvidenceRecord]:
    """Return a new list with *record* appended after validation."""
    errs = record.validate()
    if errs:
        raise EvidenceLedgerError("; ".join(errs))
    return records + [record]


_STATUS_FA = {
    "confirmed": "تأییدشده",
    "partially_confirmed": "تا حدی تأییدشده",
    "unconfirmed": "تأییدنشده",
    "refuted": "ردشده",
    "needs_more_access": "نیازمند دسترسی بیشتر",
}


def render_markdown_table(records: list[EvidenceRecord]) -> str:
    header = ("| ادعا | منبع اولیه | فایل/خط یا commit | روش راستی‌آزمایی "
              "| وضعیت | میزان اطمینان |\n"
              "|---|---|---|---|---|---|\n")
    rows = []
    for r in records:
        status = f"{_STATUS_FA.get(r.status, r.status)} ({r.status})"
        cells = [r.claim, r.source, r.locator, r.method, status, r.confidence]
        rows.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return header + "\n".join(rows) + "\n"


def summarize(records: list[EvidenceRecord]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for r in records:
        counts[r.status] = counts.get(r.status, 0) + 1
    return {"total": len(records), "by_status": counts}
