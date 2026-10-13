"""FastAPI backend for the Trust Wallet RNG Research Lab dashboard.

Security posture: binds to 127.0.0.1 only (see server.py), no shell execution,
no arbitrary file reads (adapter-level containment), CORS restricted to the
local dev origin. All numeric results come from real core computations.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from rng_lab import __version__, adapters as A
from rng_lab.store import Store

DEFAULT_SETTINGS = {
    "data_dir": "data",
    "reports_dir": "data/reports",
    "theme": "dark",
    "runner_max_workers": 2,
    "log_level": "info",
    "persistence": "sqlite",
}


# ------------------------------------------------------------- schemas
class ExperimentDef(BaseModel):
    id: str | None = None
    title: str = Field(min_length=3, max_length=200)
    question: str = ""
    objective: str = ""
    module: str = ""
    model: str = ""
    method: str = ""
    validation: str = ""
    notes: str = ""
    params_schema: dict[str, Any] = {}

class RunRequest(BaseModel):
    params: dict[str, Any] = {}

class SampleCreate(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    kind: str
    params: dict[str, Any] = {}

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in A.SAMPLE_KINDS:
            raise ValueError(f"unsupported kind {v!r}; valid: {A.SAMPLE_KINDS}")
        return v

class FindingCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    module: str = ""
    status: str = "new"
    confidence: str = "unspecified"
    severity: str = "unspecified"
    reproduction: str = ""
    limitations: str = ""
    linked_runs: list[str] = []
    linked_evidence: list[int] = []
    notes: str = ""

class FindingStatusUpdate(BaseModel):
    status: str
    note: str = ""

    @field_validator("status")
    @classmethod
    def _st(cls, v: str) -> str:
        if v not in {"new", "investigating", "confirmed", "rejected", "fixed"}:
            raise ValueError("invalid status")
        return v

class SettingsPatch(BaseModel):
    values: dict[str, Any]

class ProbeRequest(BaseModel):
    params: dict[str, Any] = {}

class TestRunRequest(BaseModel):
    suite: str


def create_app(db_path: str | Path | None = None) -> FastAPI:
    root = A.PROJECT_ROOT
    db = Path(db_path) if db_path else root / "data" / "rnglab.db"
    store = Store(db)
    jobs = A.JobManager(store)
    n = store.recover_interrupted()
    if n:
        store.add_event(None, "warning", f"recovered {n} interrupted run(s) after restart")
    for k, v in DEFAULT_SETTINGS.items():
        if store.get_setting(k) is None:
            store.set_setting(k, v)

    app = FastAPI(title="Trust Wallet RNG Research Lab", version=__version__,
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.store = store
    app.state.jobs = jobs
    app.add_middleware(CORSMiddleware, allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173"],
        allow_methods=["*"], allow_headers=["*"])

    @app.on_event("shutdown")
    def _shutdown():
        jobs.shutdown(); store.close()

    # ------------------------------------------------------------- health/overview
    @app.get("/api/health")
    def health():
        hashes = A.verify_snapshot_hashes()
        return {"status": "ok", "version": __version__,
                "core_connected": True,
                "snapshot_integrity": all(h["match"] for h in hashes),
                "snapshots": hashes}

    @app.get("/api/overview")
    def overview():
        runs = store.list_runs()
        by_status: dict[str, int] = {}
        for r in runs:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        hashes = A.verify_snapshot_hashes()
        findings = store.list_findings()
        last_test = [e for e in store.list_events(level="info", limit=500)
                     if "pytest" in e["message"]]
        env = A.env_report(include_network=False)
        return {
            "backend": "ok", "version": __version__, "python": env.get("python"),
            "os": env.get("os"), "node": env.get("node"),
            "experiments_defined": len(store.list_experiments()),
            "core_experiments_available": len(A.experiments_catalog()),
            "runs_total": len(runs), "runs_by_status": by_status,
            "samples": len(store.list_samples()),
            "findings": len(findings),
            "evidence_records": len(A.evidence_list()),
            "snapshot_integrity": {"ok": all(h["match"] for h in hashes),
                                   "details": hashes},
            "recent_events": store.list_events(limit=15),
            "last_test_run": last_test[-1]["message"] if last_test else None,
            "not_implemented": ["WASM historical artefact reconstruction "
                                "(out of scope; see docs/limitations.md)"],
        }

    @app.get("/api/modules")
    def modules():
        return {"models": A.MODEL_CATALOG,
                "core_experiments": A.experiments_catalog(),
                "sample_kinds": A.SAMPLE_KINDS,
                "test_suites": dict(A.TEST_SUITES)}

    # ------------------------------------------------------------- experiments
    @app.post("/api/experiments", status_code=201)
    def create_experiment(body: ExperimentDef):
        try:
            return store.create_experiment(body.model_dump(exclude_none=True))
        except Exception as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/experiments")
    def get_experiments():
        return {"definitions": store.list_experiments(),
                "core_registry": A.experiments_catalog()}

    @app.get("/api/experiments/{eid}")
    def get_experiment(eid: str):
        e = store.get_experiment(eid)
        if not e:
            raise HTTPException(404, f"experiment {eid} not found")
        e["runs"] = store.list_runs(experiment_id=eid)
        return e

    @app.post("/api/experiments/{eid}/runs", status_code=202)
    def start_run(eid: str, body: RunRequest):
        if eid not in A.experiments_catalog():
            raise HTTPException(400, f"{eid} is not a runnable core experiment. "
                               f"Runnable: {sorted(A.experiments_catalog())}")
        try:
            rid = jobs.submit_core_experiment(eid, body.params)
        except (ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc))
        return {"run_id": rid, "status": "queued"}

    @app.get("/api/runs")
    def all_runs(status: str | None = None, experiment_id: str | None = None):
        return store.list_runs(experiment_id=experiment_id, status=status)

    @app.get("/api/runs/{rid}")
    def get_run(rid: str):
        r = store.get_run(rid)
        if not r:
            raise HTTPException(404, f"run {rid} not found")
        r["events"] = store.list_events(run_id=rid, limit=100)
        return r

    @app.get("/api/runs/{rid}/results")
    def run_results(rid: str):
        r = store.get_run(rid)
        if not r:
            raise HTTPException(404, f"run {rid} not found")
        return {"run_id": rid, "status": r["status"], "params": r["params"],
                "result": r["result"], "error": r["error"],
                "code_version": r["code_version"], "env_snapshot": r["env_snapshot"]}

    @app.post("/api/runs/{rid}/cancel")
    def cancel_run(rid: str):
        r = store.get_run(rid)
        if not r:
            raise HTTPException(404, f"run {rid} not found")
        if r["status"] not in ("queued", "running"):
            raise HTTPException(409, f"cannot cancel run in state {r['status']!r}")
        jobs.cancel(rid)
        return {"run_id": rid, "cancellation_requested": True,
                "note": "cooperative: effective while still queued"}

    @app.post("/api/runs/{rid}/rerun", status_code=202)
    def rerun(rid: str):
        r = store.get_run(rid)
        if not r:
            raise HTTPException(404, f"run {rid} not found")
        new_id = jobs.submit_core_experiment(r["experiment_id"], r["params"])
        return {"run_id": new_id, "based_on": rid}

    # ------------------------------------------------------------- wallet lab
    @app.post("/api/wallet-lab/samples", status_code=201)
    def create_sample(body: SampleCreate):
        try:
            gen = A.generate_test_sample(body.kind, body.params)
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc))
        rec = store.create_sample({"label": body.label, "kind": body.kind,
                                   "params": body.params,
                                   "metadata": gen["metadata"],
                                   "validation": gen["validation"]})
        rec["artefact"] = {k: v for k, v in gen.items()
                           if k.startswith("artefact")}
        return rec

    @app.get("/api/wallet-lab/samples")
    def samples(kind: str | None = None, q: str | None = None,
                fmt: str | None = None):
        rows = store.list_samples(kind=kind, search=q)
        safe = [{"id": r["id"], "label": r["label"], "kind": r["kind"],
                 "created_at": r["created_at"], "params": r["params"],
                 "validation": r["validation"]} for r in rows]
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["id", "label", "kind", "created_at", "params_json"])
            for r in safe:
                w.writerow([r["id"], r["label"], r["kind"], r["created_at"],
                            json.dumps(r["params"])])
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(buf.getvalue(), media_type="text/csv")
        return safe

    @app.get("/api/wallet-lab/samples/{sid}")
    def sample_detail(sid: str):
        s = store.get_sample(sid)
        if not s:
            raise HTTPException(404, f"sample {sid} not found")
        s["interpretation_limit"] = (
            "Structural validity != funds, key control or recoverability. "
            "Samples are synthetic modelling artefacts.")
        return s

    # ------------------------------------------------------------- evidence
    @app.get("/api/evidence")
    def evidence(q: str = "", status: str = ""):
        return A.evidence_list(query=q, status=status)

    @app.get("/api/evidence/integrity")
    def evidence_integrity():
        return {"snapshots": A.verify_snapshot_hashes(),
                "policy": "expected hashes are never auto-updated; mismatch => warning"}

    @app.get("/api/evidence/{idx}")
    def evidence_one(idx: int):
        recs = A.evidence_list()
        if idx < 0 or idx >= len(recs):
            raise HTTPException(404, f"ledger record index {idx} out of range")
        return recs[idx]

    # ------------------------------------------------------------- findings
    @app.post("/api/findings", status_code=201)
    def create_finding(body: FindingCreate):
        return store.create_finding(body.model_dump())

    @app.get("/api/findings")
    def findings(status: str | None = None):
        return store.list_findings(status=status)

    @app.get("/api/findings/{fid}")
    def finding(fid: str):
        f = store.get_finding(fid)
        if not f:
            raise HTTPException(404, f"finding {fid} not found")
        return f

    @app.patch("/api/findings/{fid}/status")
    def finding_status(fid: str, body: FindingStatusUpdate):
        try:
            return store.update_finding_status(fid, body.status, body.note)
        except KeyError:
            raise HTTPException(404, f"finding {fid} not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    # ------------------------------------------------------------- comparison
    @app.get("/api/comparisons")
    def compare(ids: str = Query(..., description="comma-separated run ids")):
        rid_list = [i.strip() for i in ids.split(",") if i.strip()]
        if len(rid_list) < 2:
            raise HTTPException(400, "provide at least two run ids")
        runs = []
        for rid in rid_list:
            r = store.get_run(rid)
            if not r:
                raise HTTPException(404, f"run {rid} not found")
            runs.append(r)
        keys = sorted({k for r in runs for k in r["params"]})
        differing = [k for k in keys
                     if len({json.dumps(r["params"].get(k), sort_keys=True)
                             for r in runs}) > 1]
        versions = {r["id"]: r["code_version"] for r in runs}
        comparable = len(set(versions.values())) <= 1 and not differing
        return {"runs": [{k: r[k] for k in
                          ("id", "experiment_id", "status", "params", "result",
                           "error", "started_at", "finished_at", "code_version")}
                         for r in runs],
                "differing_params": differing,
                "code_versions": versions,
                "directly_comparable": comparable,
                "caveat": None if comparable else
                    "Runs differ in params and/or code version; differences may "
                    "be attributable to conditions, not to the compared factor."}

    # ------------------------------------------------------------- reports
    @app.post("/api/reports/run/{rid}")
    def report_run(rid: str):
        r = store.get_run(rid)
        if not r:
            raise HTTPException(404, f"run {rid} not found")
        payload = {"type": "run_report", "generated_from": "stored run data only",
                   "run": r, "linked_findings": [
                       f for f in store.list_findings() if rid in f["linked_runs"]]}
        reports_dir = root / str(store.get_setting("reports_dir", "data/reports"))
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"run_{rid}.json"
        text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        Path(path).write_text(text, encoding="utf-8")
        rec = store.record_report(f"run:{rid}", "json", str(path),
                                  A._models.sha256_bytes(text.encode()))
        return {"report": rec, "payload_preview": payload}

    @app.post("/api/reports/lab")
    def report_lab():
        ov = overview()
        payload = {"type": "lab_summary", "generated_at_utc": A._ts(),
                   "overview": ov,
                   "runs": store.list_runs(), "findings": store.list_findings()}
        reports_dir = root / str(store.get_setting("reports_dir", "data/reports"))
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / "lab_summary.json"
        text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        Path(path).write_text(text, encoding="utf-8")
        rec = store.record_report("lab", "json", str(path),
                                  A._models.sha256_bytes(text.encode()))
        return rec

    @app.get("/api/reports")
    def list_reports():
        return store.list_reports()

    # ------------------------------------------------------------- console/tests
    @app.get("/api/events")
    def events(run_id: str | None = None, level: str | None = None,
               q: str | None = None, limit: int = 200):
        return store.list_events(run_id=run_id, level=level, search=q, limit=limit)

    @app.post("/api/tests/run")
    def tests_run(body: TestRunRequest):
        try:
            res = A.run_test_suite(body.suite)
        except KeyError as exc:
            raise HTTPException(400, str(exc))
        store.add_event(None, "info",
                        f"pytest suite={body.suite} exit={res['exit_code']}")
        return res

    @app.get("/api/tests/suites")
    def tests_suites():
        return {"suites": dict(A.TEST_SUITES), "all_target": "tests/"}

    # ------------------------------------------------------------- settings/models
    @app.get("/api/settings")
    def settings_get():
        return {"defaults": DEFAULT_SETTINGS, "current": store.all_settings()}

    @app.patch("/api/settings")
    def settings_patch(body: SettingsPatch):
        allowed = set(DEFAULT_SETTINGS)
        rejected = [k for k in body.values if k not in allowed]
        for k, v in body.values.items():
            if k in allowed:
                store.set_setting(k, v)
        return {"updated": store.all_settings(), "rejected_keys": rejected,
                "note": "only operational settings are writable here; research "
                        "protocols are defined via experiment records"}

    @app.post("/api/models/{model_id}/probe")
    def model_probe(model_id: str, body: ProbeRequest | None = None):
        try:
            return A.run_model_probe(model_id, (body.params if body else {}))
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    return app
