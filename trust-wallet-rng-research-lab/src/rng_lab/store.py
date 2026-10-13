"""SQLite persistence for experiment definitions, runs, events, samples and findings.

Design rules:
- Historical evidence stays file-based (config/evidence_ledger.json + fixtures).
  The DB only *references* ledger records by id; it never copies mutable state.
- Every run stores its params, code version, environment snapshot and result so
  results are traceable to the exact settings that produced them.
- Schema is versioned via PRAGMA user_version; migrations run in order.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    question TEXT DEFAULT '',
    objective TEXT DEFAULT '',
    module TEXT DEFAULT '',
    model TEXT DEFAULT '',
    method TEXT DEFAULT '',
    validation TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    params_schema TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL REFERENCES experiments(id),
    status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')),
    params TEXT NOT NULL DEFAULT '{}',
    result TEXT,
    error TEXT,
    progress REAL,
    code_version TEXT,
    env_snapshot TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,
    run_id TEXT,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
CREATE TABLE IF NOT EXISTS samples (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    metadata TEXT NOT NULL DEFAULT '{}',
    validation TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sample_ops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL REFERENCES samples(id),
    ts TEXT NOT NULL,
    op TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    module TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','investigating','confirmed','rejected','fixed')),
    confidence TEXT DEFAULT 'unspecified',
    severity TEXT DEFAULT 'unspecified',
    reproduction TEXT DEFAULT '',
    limitations TEXT DEFAULT '',
    linked_runs TEXT NOT NULL DEFAULT '[]',
    linked_evidence TEXT NOT NULL DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    history TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    fmt TEXT NOT NULL,
    path TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            cur = self._conn.execute("PRAGMA user_version")
            version = cur.fetchone()[0]
            if version < SCHEMA_VERSION:
                self._conn.executescript(_SCHEMA)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- generic helpers -------------------------------------------------
    def _rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def _row(self, sql: str, args: tuple = ()) -> dict[str, Any] | None:
        rs = self._rows(sql, args)
        return rs[0] if rs else None

    def _exec(self, sql: str, args: tuple = ()) -> None:
        with self._lock:
            self._conn.execute(sql, args)
            self._conn.commit()

    # ---- experiments ------------------------------------------------------
    def create_experiment(self, data: dict[str, Any]) -> dict[str, Any]:
        eid = data.get("id") or f"X-{uuid.uuid4().hex[:8]}"
        self._exec(
            "INSERT INTO experiments (id,title,question,objective,module,model,"
            "method,validation,notes,params_schema,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (eid, data["title"], data.get("question", ""), data.get("objective", ""),
             data.get("module", ""), data.get("model", ""), data.get("method", ""),
             data.get("validation", ""), data.get("notes", ""),
             json.dumps(data.get("params_schema", {})), _utcnow()))
        return self.get_experiment(eid)  # type: ignore[return-value]

    def get_experiment(self, eid: str) -> dict[str, Any] | None:
        r = self._row("SELECT * FROM experiments WHERE id=?", (eid,))
        if r:
            r["params_schema"] = json.loads(r["params_schema"])
        return r

    def list_experiments(self) -> list[dict[str, Any]]:
        out = self._rows("SELECT * FROM experiments ORDER BY created_at DESC")
        for r in out:
            r["params_schema"] = json.loads(r["params_schema"])
        return out

    # ---- runs ---------------------------------------------------------------
    def create_run(self, experiment_id: str, params: dict[str, Any],
                   code_version: str = "", env_snapshot: dict | None = None) -> dict[str, Any]:
        rid = f"R-{uuid.uuid4().hex[:10]}"
        self._exec(
            "INSERT INTO runs (id,experiment_id,status,params,code_version,env_snapshot,"
            "progress,created_at) VALUES (?,?,'queued',?,?,?,NULL,?)",
            (rid, experiment_id, json.dumps(params), code_version,
             json.dumps(env_snapshot or {}), _utcnow()))
        self.add_event(rid, "info", f"run {rid} queued for experiment {experiment_id}")
        return self.get_run(rid)  # type: ignore[return-value]

    def update_run(self, rid: str, **fields: Any) -> None:
        allowed = {"status", "result", "error", "progress", "started_at", "finished_at"}
        cols, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                raise ValueError(f"field not updatable: {k}")
            cols.append(f"{k}=?")
            vals.append(json.dumps(v) if k == "result" else v)
        if not cols:
            return
        vals.append(rid)
        self._exec(f"UPDATE runs SET {','.join(cols)} WHERE id=?", tuple(vals))

    def get_run(self, rid: str) -> dict[str, Any] | None:
        r = self._row("SELECT * FROM runs WHERE id=?", (rid,))
        if r:
            r["params"] = json.loads(r["params"])
            r["result"] = json.loads(r["result"]) if r["result"] else None
            r["env_snapshot"] = json.loads(r["env_snapshot"]) if r["env_snapshot"] else {}
        return r

    def list_runs(self, experiment_id: str | None = None,
                  status: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM runs WHERE 1=1", []
        if experiment_id:
            sql += " AND experiment_id=?"; args.append(experiment_id)
        if status:
            sql += " AND status=?"; args.append(status)
        sql += " ORDER BY created_at DESC"
        out = self._rows(sql, tuple(args))
        for r in out:
            r["params"] = json.loads(r["params"])
            r["result"] = json.loads(r["result"]) if r["result"] else None
        return out

    def recover_interrupted(self) -> int:
        """After a restart, any run still marked running/queued cannot be resumed
        honestly: mark it failed with an explicit reason (never silently lost)."""
        n = len(self._rows("SELECT id FROM runs WHERE status IN ('queued','running')"))
        if n:
            self._exec(
                "UPDATE runs SET status='failed', error='interrupted by server restart',"
                " finished_at=? WHERE status IN ('queued','running')", (_utcnow(),))
        return n

    # ---- events -------------------------------------------------------------
    def add_event(self, run_id: str | None, level: str, message: str) -> None:
        self._exec("INSERT INTO events (ts,level,run_id,message) VALUES (?,?,?,?)",
                   (_utcnow(), level, run_id, message))

    def list_events(self, run_id: str | None = None, level: str | None = None,
                    search: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM events WHERE 1=1", []
        if run_id:
            sql += " AND run_id=?"; args.append(run_id)
        if level:
            sql += " AND level=?"; args.append(level)
        if search:
            sql += " AND message LIKE ?"; args.append(f"%{search}%")
        sql += " ORDER BY id DESC LIMIT ?"; args.append(min(limit, 1000))
        return self._rows(sql, tuple(args))

    # ---- samples --------------------------------------------------------------
    def create_sample(self, data: dict[str, Any]) -> dict[str, Any]:
        sid = data.get("id") or f"S-{uuid.uuid4().hex[:8]}"
        self._exec("INSERT INTO samples (id,label,kind,params,metadata,validation,created_at)"
                   " VALUES (?,?,?,?,?,?,?)",
                   (sid, data["label"], data["kind"], json.dumps(data.get("params", {})),
                    json.dumps(data.get("metadata", {})), json.dumps(data.get("validation", {})),
                    _utcnow()))
        self.log_sample_op(sid, "created")
        return self.get_sample(sid)  # type: ignore[return-value]

    def get_sample(self, sid: str) -> dict[str, Any] | None:
        r = self._row("SELECT * FROM samples WHERE id=?", (sid,))
        if r:
            for k in ("params", "metadata", "validation"):
                r[k] = json.loads(r[k])
            r["ops"] = self._rows(
                "SELECT ts,op,detail FROM sample_ops WHERE sample_id=? ORDER BY id", (sid,))
        return r

    def list_samples(self, kind: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM samples WHERE 1=1", []
        if kind:
            sql += " AND kind=?"; args.append(kind)
        if search:
            sql += " AND (label LIKE ? OR id LIKE ?)"; args += (f"%{search}%", f"%{search}%")
        sql += " ORDER BY created_at DESC"
        out = self._rows(sql, tuple(args))
        for r in out:
            for k in ("params", "metadata", "validation"):
                r[k] = json.loads(r[k])
        return out

    def log_sample_op(self, sid: str, op: str, detail: str = "") -> None:
        self._exec("INSERT INTO sample_ops (sample_id,ts,op,detail) VALUES (?,?,?,?)",
                   (sid, _utcnow(), op, detail))

    # ---- findings -------------------------------------------------------------
    def create_finding(self, data: dict[str, Any]) -> dict[str, Any]:
        fid = data.get("id") or f"F-{uuid.uuid4().hex[:8]}"
        hist = json.dumps([{"ts": _utcnow(), "status": data.get("status", "new"),
                            "note": "created"}])
        self._exec("INSERT INTO findings (id,title,description,module,status,confidence,"
                   "severity,reproduction,limitations,linked_runs,linked_evidence,notes,"
                   "created_at,history) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (fid, data["title"], data.get("description", ""), data.get("module", ""),
                    data.get("status", "new"), data.get("confidence", "unspecified"),
                    data.get("severity", "unspecified"), data.get("reproduction", ""),
                    data.get("limitations", ""),
                    json.dumps(data.get("linked_runs", [])),
                    json.dumps(data.get("linked_evidence", [])),
                    data.get("notes", ""), _utcnow(), hist))
        return self.get_finding(fid)  # type: ignore[return-value]

    def get_finding(self, fid: str) -> dict[str, Any] | None:
        r = self._row("SELECT * FROM findings WHERE id=?", (fid,))
        if r:
            r["linked_runs"] = json.loads(r["linked_runs"])
            r["linked_evidence"] = json.loads(r["linked_evidence"])
            r["history"] = json.loads(r["history"])
        return r

    def list_findings(self, status: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM findings", []
        if status:
            sql += " WHERE status=?"; args.append(status)
        sql += " ORDER BY created_at DESC"
        out = self._rows(sql, tuple(args))
        for r in out:
            r["linked_runs"] = json.loads(r["linked_runs"])
            r["linked_evidence"] = json.loads(r["linked_evidence"])
            r["history"] = json.loads(r["history"])
        return out

    def update_finding_status(self, fid: str, status: str, note: str = "") -> dict[str, Any]:
        valid = {"new", "investigating", "confirmed", "rejected", "fixed"}
        if status not in valid:
            raise ValueError(f"invalid finding status: {status!r}; valid: {sorted(valid)}")
        f = self.get_finding(fid)
        if not f:
            raise KeyError(f"finding not found: {fid}")
        hist = f["history"] + [{"ts": _utcnow(), "status": status, "note": note}]
        self._exec("UPDATE findings SET status=?, history=? WHERE id=?",
                   (status, json.dumps(hist), fid))
        return self.get_finding(fid)  # type: ignore[return-value]

    # ---- settings ------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        r = self._row("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(r["value"]) if r else default

    def set_setting(self, key: str, value: Any) -> None:
        self._exec("INSERT INTO settings (key,value) VALUES (?,?)"
                   " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, json.dumps(value)))

    def all_settings(self) -> dict[str, Any]:
        return {r["key"]: json.loads(r["value"]) for r in
                self._rows("SELECT key,value FROM settings")}

    # ---- reports index ---------------------------------------------------------
    def record_report(self, scope: str, fmt: str, path: str, payload_hash: str) -> dict[str, Any]:
        rid = f"REP-{uuid.uuid4().hex[:8]}"
        self._exec("INSERT INTO reports (id,scope,fmt,path,payload_hash,created_at)"
                   " VALUES (?,?,?,?,?,?)", (rid, scope, fmt, path, payload_hash, _utcnow()))
        return {"id": rid, "scope": scope, "format": fmt, "path": path,
                "payload_hash": payload_hash, "created_at": _utcnow()}

    def list_reports(self) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM reports ORDER BY created_at DESC")
