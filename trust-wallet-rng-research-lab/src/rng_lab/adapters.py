"""Adapter layer: safe, read-oriented bridge between the web platform and the
`rng_research` core.

Rules enforced here:
- No arbitrary paths from the API: every file access goes through PROJECT_ROOT
  containment checks (path-traversal protection).
- No shell commands from the API: only pre-registered experiment handlers run.
- Historical fixtures are exposed read-only; all derived artifacts go to data/.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
LEDGER_PATH = PROJECT_ROOT / "config" / "evidence_ledger.json"
SNAPSHOT_DIR = PROJECT_ROOT / "fixtures" / "source-snapshots"
PROVENANCE_PATH = SNAPSHOT_DIR / "provenance.json"

sys.path.insert(0, str(PROJECT_ROOT / "src"))

from rng_research import evidence as _ev          # noqa: E402
from rng_research import experiment_runner as _er  # noqa: E402
from rng_research import environment as _env       # noqa: E402
from rng_research import models as _models         # noqa: E402
from rng_research import secure_rng as _srng       # noqa: E402
from rng_research import source_analysis as _sa    # noqa: E402
from rng_research import patch_analysis as _pa     # noqa: E402
from rng_research import mt19937_reference as _mt  # noqa: E402


def safe_read(path_str: str) -> Path:
    """Resolve path_str and refuse anything outside PROJECT_ROOT."""
    p = (PROJECT_ROOT / path_str).resolve() if not Path(path_str).is_absolute() \
        else Path(path_str).resolve()
    root = PROJECT_ROOT.resolve()
    if not str(p).startswith(str(root)):
        raise PermissionError(f"path escapes project root: {path_str!r}")
    return p


# ------------------------------------------------------------------ evidence
def load_evidence_records() -> list[_models.EvidenceRecord]:
    return _ev.load_ledger(LEDGER_PATH)


def evidence_list(query: str = "", status: str = "") -> list[dict[str, Any]]:
    recs = load_evidence_records()
    out = []
    for i, r in enumerate(recs):
        d = _models.evidence_to_dict(r) if hasattr(_models, "evidence_to_dict") \
            else r.__dict__
        d["record_index"] = i
        if status and d.get("status") != status:
            continue
        if query and query.lower() not in json.dumps(d, ensure_ascii=False).lower():
            continue
        out.append(d)
    return out


def verify_snapshot_hashes() -> list[dict[str, Any]]:
    """Raw-byte SHA-256 check of every snapshot listed in provenance.json.
    Never mutates expected values; reports mismatches as warnings."""
    prov = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    entries = prov.get("snapshots", []) if isinstance(prov, dict) else prov
    results = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        fname = (entry.get("local_file") or entry.get("file")
                 or entry.get("name") or entry.get("path"))
        expected = ""
        for hk in ("sha256", "sha256_local_file", "raw_sha256"):
            if entry.get(hk):
                expected = entry[hk].lower(); break
        p = SNAPSHOT_DIR / fname
        actual = _models.sha256_file(str(p)) if p.exists() else None
        results.append({
            "file": fname,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "exists": p.exists(),
            "match": bool(actual and actual == expected),
        })
    return results


# ------------------------------------------------------------------ models
MODEL_CATALOG: dict[str, dict[str, Any]] = {
    "mt19937-reference": {
        "purpose": "Independent MT19937 engine used for conformance testing.",
        "origin": "src/rng_research/mt19937_reference.py (from published spec)",
        "inputs": ["uint32 seed"],
        "params": ["seed:int"],
        "output": "first outputs after seeding",
        "validation": "verified against g++ std::mt19937 oracle (fixtures/references)",
        "limitations": "bit-level equivalence with historical WASM binary UNVERIFIED",
        "tests": ["tests/test_mt19937_conformance.py"],
        "status": "implemented / externally verified vs libstdc++",
    },
    "vulnerable-model": {
        "purpose": "Architecture model of vulnerable random_buffer(): per-call reseed + uint32 truncation.",
        "origin": "reconstructed from fixtures/source-snapshots/Random.cpp@69b2da9826df.txt lines 15-21",
        "inputs": ["seed sequence (integers)", "buffer length"],
        "params": ["seeds:list[int]", "length:int"],
        "output": "bytes produced under the modeled contract",
        "validation": "static analysis of byte-exact snapshot; NOT a WASM execution",
        "limitations": "faithful to source structure, not bit-level to shipped binary",
        "tests": ["tests/test_secure_rng.py"],
        "status": "implemented (architecture-faithful model)",
    },
    "secure-rng": {
        "purpose": "os.urandom-backed CSPRNG reference behaviour.",
        "origin": "src/rng_research/secure_rng.py",
        "inputs": ["n bytes"],
        "params": [],
        "output": "cryptographic random bytes",
        "validation": "statistical battery (documented as necessary-not-sufficient)",
        "limitations": "statistical tests do not prove cryptographic security",
        "tests": ["tests/test_secure_rng.py", "tests/test_rng_properties.py"],
        "status": "implemented",
    },
}


def run_model_probe(model_id: str, params: dict[str, Any]) -> dict[str, Any]:
    """Deterministic probes on models — real computation, no fabricated output."""
    if model_id == "mt19937-reference":
        seed = int(params.get("seed", 0)) & 0xFFFFFFFF
        eng = _mt.MT19937Reference()
        eng.seed_scalar(seed)
        return {"model": model_id, "seed": seed,
                "first_5_outputs": [eng.next_uint32() for _ in range(5)]}
    if model_id == "vulnerable-model":
        seeds = [int(s) & 0xFFFFFFFF for s in params.get("seeds", [1, 2, 3])]
        length = int(params.get("length", 16))
        if not 1 <= length <= 4096:
            raise ValueError("length must be in [1, 4096]")
        bufs = _srng.model_per_call_reseed_sequence(seeds, length)  # list[bytes]
        seq = b"".join(bufs)
        return {"model": model_id, "seeds": seeds, "length": length,
                "hex": seq.hex(), "identical_for_equal_seeds":
                seq == _srng.model_per_call_reseed_sequence(list(seeds), length)}
    if model_id == "secure-rng":
        n = int(params.get("n", 32))
        if not 1 <= n <= 65536:
            raise ValueError("n must be in [1, 65536]")
        b = _srng.secure_bytes(n)
        return {"model": model_id, "n": n, "sha256_of_sample": _models.sha256_bytes(b),
                "note": "non-deterministic by design"}
    raise KeyError(f"unknown model: {model_id}")


# ------------------------------------------------------------------ experiments
class JobManager:
    """Non-blocking runner: executes registered experiment handlers in a small
    thread pool and records state transitions through the Store."""

    def __init__(self, store, max_workers: int = 2):
        self.store = store
        self._pool = ThreadPoolExecutor(max_workers=max_workers,
                                       thread_name_prefix="rnglab-job")
        self._cancel: set[str] = set()
        self._lock = threading.Lock()

    def handlers(self) -> dict[str, Callable]:
        return getattr(_er, "_EXPERIMENTS", {})

    def submit_core_experiment(self, exp_id: str, params: dict[str, Any]) -> str:
        """Run one of the pre-registered research-core experiments (E1..E5)."""
        if exp_id not in self.handlers():
            raise KeyError(f"experiment not registered: {exp_id}")
        run = self.store.create_run(exp_id, params, code_version=_code_version())
        self._pool.submit(self._execute, run["id"], exp_id, params)
        return run["id"]

    def _execute(self, rid: str, exp_id: str, params: dict[str, Any]) -> None:
        with self._lock:
            if rid in self._cancel:
                self._cancel.discard(rid)
                self.store.update_run(rid, status="cancelled",
                                      finished_at=_ts(), error="cancelled before start")
                self.store.add_event(rid, "warning", f"run {rid} cancelled")
                return
        self.store.update_run(rid, status="running", started_at=_ts(), progress=0.0)
        try:
            result = _er.run_experiment(exp_id, params)
            payload = result.to_dict() if hasattr(result, "to_dict") else result.__dict__
            self.store.update_run(rid, status="completed", finished_at=_ts(),
                                  progress=1.0, result=payload)
            self.store.add_event(rid, "info", f"run {rid} completed ({exp_id})")
        except Exception as exc:  # recorded honestly, never swallowed
            tb = traceback.format_exc(limit=8)
            self.store.update_run(rid, status="failed", finished_at=_ts(),
                                  error=f"{type(exc).__name__}: {exc}",
                                  result={"traceback_local": tb})
            self.store.add_event(rid, "error", f"run {rid} failed: {exc}")

    def cancel(self, rid: str) -> bool:
        """Cooperative cancellation: only effective while still queued."""
        with self._lock:
            self._cancel.add(rid)
        return True

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)


def _ts() -> str:
    return _models.utc_now_iso()


def _code_version() -> str:
    try:
        out = subprocess.run(["git", "-C", str(PROJECT_ROOT), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


# ------------------------------------------------------------------ wallet lab
def generate_test_sample(kind: str, params: dict[str, Any]) -> dict[str, Any]:
    """Create SYNTHETIC test samples only. This is an isolated research helper:
    - it never derives or stores real user keys/mnemonics
    - outputs are labelled clearly as synthetic modelling artefacts
    """
    label = "SYNTHETIC-MODELLING — NOT a real wallet, NOT Trust Wallet compatible-verified"
    if kind == "seeded-buffer":
        seed = int(params.get("seed", 0)) & 0xFFFFFFFF
        length = int(params.get("length", 32))
        if not 1 <= length <= 4096:
            raise ValueError("length must be in [1, 4096]")
        buf = _srng.model_random_buffer_seeded(seed, length)
        meta = {"seed": seed, "length": length,
                "generator": "vulnerable-model (per-call reseed architecture model)",
                "determinism_check": buf == _srng.model_random_buffer_seeded(seed, length)}
        validation = {"structural": "ok", "interpretation_limit":
                      "behavioural model only; bit-level fidelity to historical WASM UNVERIFIED"}
        return {"kind": kind, "label": label, "params": params,
                "metadata": meta, "validation": validation,
                "artefact_hex": buf.hex()}
    if kind == "secure-bytes":
        n = int(params.get("n", 32))
        if not 1 <= n <= 65536:
            raise ValueError("n must be in [1, 65536]")
        b = _srng.secure_bytes(n)
        return {"kind": kind, "label": label, "params": {"n": n},
                "metadata": {"generator": "os.urandom CSPRNG"},
                "validation": {"structural": "ok",
                               "interpretation_limit":
                               "statistical quality ≠ proof of cryptographic security"},
                "artefact_sha256": _models.sha256_bytes(b)}
    raise ValueError(f"unsupported sample kind: {kind!r}. supported: seeded-buffer, secure-bytes")


SAMPLE_KINDS = ["seeded-buffer", "secure-bytes"]


# ------------------------------------------------------------------ tests center
TEST_SUITES = {
    "unit": ["tests/test_rng_properties.py", "tests/test_secure_rng.py",
             "tests/test_evidence.py", "tests/test_models" if False else "tests/test_evidence.py"],
    "conformance": ["tests/test_mt19937_conformance.py"],
    "integrity": ["tests/test_fixtures_integrity.py"],
    "integration": ["tests/test_experiment_runner.py", "tests/test_report_generator.py",
                    "tests/test_cli.py"],
    "analysis": ["tests/test_source_analysis.py", "tests/test_patch_analysis.py"],
}
# de-dup while preserving order (unit list kept explicit & honest)
TEST_SUITES["unit"] = ["tests/test_rng_properties.py", "tests/test_secure_rng.py",
                       "tests/test_evidence.py"]


def run_test_suite(suite: str, timeout: int = 300) -> dict[str, Any]:
    """Run a *pre-registered* pytest target only — never arbitrary commands."""
    if suite == "all":
        target: list[str] = ["tests"]
    elif suite in TEST_SUITES:
        target = TEST_SUITES[suite]
    else:
        raise KeyError(f"unknown suite {suite!r}; valid: all,{','.join(TEST_SUITES)}")
    cmd = [sys.executable, "-m", "pytest", "-q", *target]
    t0 = _ts()
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True,
                          text=True, timeout=timeout)
    return {"suite": suite, "command": " ".join(cmd), "started_at": t0,
            "finished_at": _ts(), "exit_code": proc.returncode,
            "stdout_tail": proc.stdout[-4000:], "stderr_tail": proc.stderr[-2000:]}


# ------------------------------------------------------------------ misc core
def env_report(include_network: bool = False) -> dict[str, Any]:
    return _env.full_report(include_network=include_network)


def experiments_catalog() -> dict[str, Any]:
    return _er.list_experiments()


def analyze_snapshot(name: str) -> dict[str, Any]:
    p = safe_read(str(SNAPSHOT_DIR / name))
    res = _sa.analyze_source_file(str(p))
    d = res.to_dict() if hasattr(res, "to_dict") else res.__dict__
    d["classification"] = _sa.classify_snapshot(res)
    return d
