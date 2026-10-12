"""Report generation: Markdown + JSON from evidence ledger, analyses and runs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .evidence import render_markdown_table, summarize
from .models import EvidenceRecord, ExperimentRun


class ReportError(Exception):
    """Raised when inputs cannot be turned into a report."""


def build_report_payload(records: list[EvidenceRecord],
                         runs: list[ExperimentRun]) -> dict[str, Any]:
    payload = {
        "tool": "rng_research",
        "tool_version": __version__,
        "subject": "CVE-2023-31290 / GHSA-pm4f-pggw-8jwc — Trust Wallet wallet-core WASM RNG",
        "evidence_summary": summarize(records),
        "evidence_records": [r.to_dict() for r in records],
        "experiments": [r.to_dict() for r in runs],
        "separation_note": (
            "'real-evidence' runs operate on byte-exact upstream snapshots; "
            "'modelling' runs are synthetic demonstrations; 'security-fix' runs "
            "exercise real CSPRNGs. Do not conflate categories."
        ),
    }
    return payload


def write_json_report(payload: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                 encoding="utf-8")
    return p


def _fmt(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:.5g}"
    return str(v)


def write_markdown_report(payload: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# گزارش تحقیق — {payload['subject']}")
    lines.append("")
    lines.append(f"- ابزار: `rng_research` نسخه {payload['tool_version']}")
    lines.append(f"- یادداشت جداسازی مشاهدات: {payload['separation_note']}")
    lines.append("")
    lines.append("## دفتر شواهد")
    lines.append("")
    s = payload["evidence_summary"]
    lines.append(f"مجموع رکوردها: **{s['total']}** — " +
                 ", ".join(f"`{k}`: {v}" for k, v in sorted(s["by_status"].items())))
    lines.append("")
    recs = [EvidenceRecord.from_dict(r) for r in payload["evidence_records"]]
    lines.append(render_markdown_table(recs))
    lines.append("## آزمایش‌ها")
    for run in payload["experiments"]:
        lines.append("")
        lines.append(f"### {run['experiment_id']}  · دسته: `{run['category']}`")
        lines.append(f"- شناسه اجرا: `{run['run_id']}` — شروع: {run['started_at']} — پایان: {run['finished_at']}")
        lines.append(f"- نسخه ابزار: {run['tool_version']} · پایتون: {run['python_version']}")
        lines.append(f"- پارامترها: `{json.dumps(run['parameters'], ensure_ascii=False)}`")
        res = run.get("results", {})
        if res.get("skipped"):
            lines.append(f"- **رد شد**: {res.get('reason')}")
        else:
            lines.append("- نتایج:")
            _render_dict(res, lines, indent=2)
        if run.get("provenance_note"):
            lines.append(f"- منشأ: {run['provenance_note']}")
        for lim in run.get("limitations", []):
            lines.append(f"- محدودیت: {lim}")
    lines.append("")
    lines.append("---")
    lines.append("این گزارش صرفاً بازسازی فنی/آزمایشگاهی یک آسیب‌پذیری تاریخی است و "
                 "هیچ گردش‌کار عملیاتی استخراج کلید یا دسترسی به دارایی افراد را شامل نمی‌شود.")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _render_dict(d: dict[str, Any], lines: list[str], indent: int) -> None:
    pad = " " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{pad}- `{k}`:")
            _render_dict(v, lines, indent + 2)
        elif isinstance(v, list):
            lines.append(f"{pad}- `{k}` ({len(v)} مورد):")
            for item in v[:12]:
                if isinstance(item, dict):
                    lines.append(f"{pad}  - " + json.dumps(item, ensure_ascii=False))
                else:
                    lines.append(f"{pad}  - {_fmt(item)}")
        else:
            lines.append(f"{pad}- `{k}`: {_fmt(v)}")
