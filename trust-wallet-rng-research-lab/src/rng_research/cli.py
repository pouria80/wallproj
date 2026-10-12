"""rng_research CLI — argparse-based, exit codes: 0 ok, 2 usage/input error, 3 runtime failure."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import __version__
from . import environment, evidence as ev_mod
from .evidence import EvidenceLedgerError
from .experiment_runner import ExperimentError, list_experiments, run_experiment, run_suite
from .models import EvidenceRecord
from .patch_analysis import PatchError, compare_files, verify_patch_file
from .report_generator import build_report_payload, write_json_report, write_markdown_report
from .source_analysis import SourceAnalysisError, analyze_source_file, classify_snapshot

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = ROOT / "config" / "evidence_ledger.json"
DEFAULT_CONFIG = ROOT / "config" / "experiments.json"
SNAP_VULN = ROOT / "fixtures/source-snapshots/Random.cpp@69b2da9826df.txt"
SNAP_FIXED = ROOT / "fixtures/source-snapshots/Random.cpp@d3c2eee16b15.txt"
PATCH_FILE = ROOT / "fixtures/patches/d3c2eee16b15.diff"


def _out(msg: str = "") -> None:
    print(msg)


def cmd_info(args: argparse.Namespace) -> int:
    _out(f"rng_research v{__version__} — research lab for CVE-2023-31290 (wallet-core WASM RNG)")
    env = environment.full_report(include_network=args.network)
    _out(json.dumps(env, indent=2, ensure_ascii=False))
    return 0 if env["all_required_ok"] else 3


def cmd_check_environment(args: argparse.Namespace) -> int:
    env = environment.full_report(include_network=True)
    _out(json.dumps(env, indent=2, ensure_ascii=False))
    ok = env["all_required_ok"]
    _out("\nREQUIRED CHECKS: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 3


def cmd_analyze_source(args: argparse.Namespace) -> int:
    try:
        result = analyze_source_file(args.path)
    except SourceAnalysisError as e:
        _out(f"error: {e}")
        return 2
    cls = classify_snapshot(result)
    _out(f"file      : {result.path}")
    _out(f"sha256    : {result.sha256}")
    _out(f"class     : {cls}")
    _out(f"summary   : {result.summary}")
    _out(f"findings  : {len(result.findings)}")
    for f in result.findings:
        _out(f"  L{f.line:>3} [{f.kind}] {f.name}: {f.snippet}")
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        _out(f"json written: {args.json}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    a = Path(args.a) if args.a else SNAP_VULN
    b = Path(args.b) if args.b else SNAP_FIXED
    try:
        comp = compare_files(a, b)
    except PatchError as e:
        _out(f"error: {e}")
        return 2
    _out(f"A={comp.file_a}\nB={comp.file_b}")
    st = comp.stats
    _out(f"identical={st.identical} added={st.added} removed={st.removed} hunks={st.changed_hunks}")
    for kc in comp.key_changes:
        _out(f"* {kc}")
    if args.diff:
        Path(args.diff).write_text(comp.unified_diff, encoding="utf-8")
        _out(f"unified diff written: {args.diff}")
    if not args.a and not args.b:
        # integrity check of the stored patch fixture too
        ok = verify_patch_file(PATCH_FILE, SNAP_VULN, SNAP_FIXED)
        _out(f"stored patch fixture matches recomputed diff: {ok}")
        return 0 if ok else 3
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    try:
        records = ev_mod.load_ledger(path)
    except EvidenceLedgerError as e:
        _out(f"error: {e}")
        return 2
    errors = ev_mod.validate_ledger(records)
    summ = ev_mod.summarize(records)
    if args.action == "list":
        for i, r in enumerate(records):
            _out(f"[{i}] ({r.status}/{r.confidence}) {r.claim}")
    elif args.action == "validate":
        if errors:
            for e in errors:
                _out(f"INVALID: {e}")
            return 2
        _out(f"ledger OK: {summ['total']} records, statuses={summ['by_status']}")
    elif args.action == "table":
        _out(ev_mod.render_markdown_table(records))
    elif args.action == "add":
        rec = EvidenceRecord(claim=args.claim, source=args.source,
                             locator=args.locator, method=args.method,
                             status=args.status, confidence=args.confidence or "medium",
                             notes=args.notes or "")
        try:
            records2 = ev_mod.add_record(records, rec)
        except EvidenceLedgerError as e:
            _out(f"error: {e}")
            return 2
        ev_mod.save_ledger(records2, path)
        _out(f"record appended to {path}")
    return 0


def cmd_run_experiments(args: argparse.Namespace) -> int:
    cfg = Path(args.config)
    outdir = Path(args.out)
    try:
        if args.experiment:
            params = json.loads(args.params) if args.params else {}
            run = run_experiment(args.experiment, params)
            outdir.mkdir(parents=True, exist_ok=True)
            p = outdir / f"{run.run_id}.json"
            p.write_text(json.dumps(run.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            _out(f"run {run.run_id} -> {p}")
            _out(json.dumps(run.results, indent=2)[:2000])
        else:
            runs = run_suite(cfg, outdir)
            _out(f"{len(runs)} experiment run(s) recorded under {outdir}")
            for r in runs:
                skipped = r.results.get("skipped")
                _out(f"- {r.experiment_id} [{r.category}] {'SKIPPED: ' + str(r.results.get('reason')) if skipped else 'OK'}")
    except ExperimentError as e:
        _out(f"error: {e}")
        return 2
    except json.JSONDecodeError as e:
        _out(f"error: invalid --params JSON: {e}")
        return 2
    return 0


def cmd_list_experiments(args: argparse.Namespace) -> int:
    for k, v in list_experiments().items():
        _out(f"{k} [{v['category']}] — {v['description']}")
    return 0


def cmd_run_tests(args: argparse.Namespace) -> int:
    cmd = [sys.executable, "-m", "pytest", str(ROOT / "tests"), "-q"]
    _out("$ " + " ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(ROOT))
    return proc.returncode


def cmd_report(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger)
    try:
        records = ev_mod.load_ledger(ledger_path)
    except EvidenceLedgerError as e:
        _out(f"error: {e}")
        return 2
    artifacts = Path(args.artifacts)
    runs = []
    if artifacts.is_dir():
        from .models import ExperimentRun
        for f in sorted(artifacts.glob("*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            runs.append(ExperimentRun(
                run_id=d["run_id"], experiment_id=d["experiment_id"],
                category=d["category"], started_at=d["started_at"],
                finished_at=d["finished_at"], tool_version=d["tool_version"],
                python_version=d["python_version"], parameters=d["parameters"],
                results=d["results"], limitations=d.get("limitations", []),
                provenance_note=d.get("provenance_note", "")))
    if not runs:
        _out(f"warning: no experiment artifacts found in {artifacts}; "
             f"run `run-experiments` first.")
    payload = build_report_payload(records, runs)
    outdir = Path(args.out)
    jp = write_json_report(payload, outdir / "report.json")
    mp = write_markdown_report(payload, outdir / "report.md")
    _out(f"wrote {jp}")
    _out(f"wrote {mp}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="rng-research",
        description="Research lab for the historical Trust Wallet wallet-core WASM RNG vulnerability (CVE-2023-31290).")
    ap.add_argument("--version", action="version", version=f"rng_research {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="project + environment info")
    p.add_argument("--network", action="store_true", help="also probe internet reachability")
    p.set_defaults(fn=cmd_info)

    p = sub.add_parser("check-environment", help="verify prerequisites")
    p.set_defaults(fn=cmd_check_environment)

    p = sub.add_parser("analyze-source", help="static analysis of a C++ RNG snapshot")
    p.add_argument("path", help="local text file with C++ source")
    p.add_argument("--json", help="optional output path for JSON result")
    p.set_defaults(fn=cmd_analyze_source)

    p = sub.add_parser("compare", help="compare two snapshots (defaults: upstream vulnerable vs fixed)")
    p.add_argument("a", nargs="?", help="file A (default: bundled vulnerable snapshot)")
    p.add_argument("b", nargs="?", help="file B (default: bundled fixed snapshot)")
    p.add_argument("--diff", help="optional path to write unified diff")
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("evidence", help="inspect/validate/extend the evidence ledger")
    p.add_argument("action", choices=["list", "validate", "table", "add"])
    p.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p.add_argument("--claim"); p.add_argument("--source"); p.add_argument("--locator")
    p.add_argument("--method"); p.add_argument("--status")
    p.add_argument("--confidence"); p.add_argument("--notes")
    p.set_defaults(fn=cmd_evidence)

    p = sub.add_parser("list-experiments", help="show available experiments")
    p.set_defaults(fn=cmd_list_experiments)

    p = sub.add_parser("run-experiments", help="run one or all configured experiments")
    p.add_argument("--config", default=str(DEFAULT_CONFIG))
    p.add_argument("--out", default=str(ROOT / "artifacts"))
    p.add_argument("--experiment", help="single experiment id")
    p.add_argument("--params", help="JSON object of parameters (with --experiment)")
    p.set_defaults(fn=cmd_run_experiments)

    p = sub.add_parser("run-tests", help="execute pytest suite")
    p.set_defaults(fn=cmd_run_tests)

    p = sub.add_parser("report", help="generate Markdown+JSON report from ledger & artifacts")
    p.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p.add_argument("--artifacts", default=str(ROOT / "artifacts"))
    p.add_argument("--out", default=str(ROOT / "reports"))
    p.set_defaults(fn=cmd_report)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except FileExistsError as e:  # pragma: no cover
        _out(f"filesystem error: {e}")
        return 3
    except PermissionError as e:  # pragma: no cover
        _out(f"permission error: {e}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
