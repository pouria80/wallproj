"""Experiment runner: executes the three experiment categories and records
reproducible run metadata (run_id, timestamps, tool version, parameters).

Categories (kept strictly separate in outputs):
  * real-evidence   — analyses over byte-exact upstream snapshots & patch
  * modelling       — synthetic models of the vulnerable mt19937 behaviour
  * security-fix    — CSPRNG behaviour tests + optional Node.js emulation of
                      the FIXED Random.cpp JS bridge (runs only if node exists)

No experiment here searches key spaces, derives real wallets, or touches
third-party funds. Scope is behavioural verification only.
"""
from __future__ import annotations

import json
import platform
import subprocess
import uuid
from pathlib import Path
from typing import Any

from . import __version__
from .models import ExperimentRun, utc_now_iso
from .rng_properties import run_all_tests, entropy_estimate
from .secure_rng import (model_effective_state_space, model_random_buffer_seeded,
                         secure_bytes)
from .source_analysis import analyze_source_file, classify_snapshot


class ExperimentError(Exception):
    """Raised when an experiment cannot be executed."""


PROJECT_ROOT = Path(__file__).resolve().parents[2]

EXPERIMENT_CATEGORIES = {"real-evidence", "modelling", "security-fix"}

# ---------------------------------------------------------------------------
# A. real-evidence experiments
# ---------------------------------------------------------------------------

def exp_real_evidence(params: dict[str, Any]) -> tuple[dict[str, Any], list[str], str]:
    vuln = PROJECT_ROOT / "fixtures/source-snapshots/Random.cpp@69b2da9826df.txt"
    fixed = PROJECT_ROOT / "fixtures/source-snapshots/Random.cpp@d3c2eee16b15.txt"
    for p in (vuln, fixed):
        if not p.exists():
            raise ExperimentError(f"required snapshot missing: {p}")
    a = analyze_source_file(vuln)
    b = analyze_source_file(fixed)
    results = {
        "vulnerable_snapshot": {
            "path": str(vuln.relative_to(PROJECT_ROOT)), "sha256": a.sha256,
            "classification": classify_snapshot(a), "summary": a.summary,
            "findings_count": len(a.findings),
        },
        "fixed_snapshot": {
            "path": str(fixed.relative_to(PROJECT_ROOT)), "sha256": b.sha256,
            "classification": classify_snapshot(b), "summary": b.summary,
            "findings_count": len(b.findings),
        },
        "expected_vuln_sha256": "f8dea1b9bd1e7057a0f7166ef372e3b34fc4a96eb7fa9e31bbd137beb8c5aab1",
        "sha_matches_upstream_record": a.sha256 == "f8dea1b9bd1e7057a0f7166ef372e3b34fc4a96eb7fa9e31bbd137beb8c5aab1",
    }
    limitations = [
        "Static analysis of source text only; the historical WASM binary was not rebuilt.",
        "Classification reflects the RNG layer of wallet-core's WASM port, not every code path of every extension release.",
    ]
    prov = ("Inputs are byte-exact copies fetched from trustwallet/wallet-core at commits "
            "69b2da9826df (parent of fix) and d3c2eee16b15 (fix, release 3.1.1). See "
            "fixtures/source-snapshots/provenance.json.")
    return results, limitations, prov


# ---------------------------------------------------------------------------
# B. modelling experiments
# ---------------------------------------------------------------------------

def exp_modelling_seed_collapse(params: dict[str, Any]) -> tuple[dict[str, Any], list[str], str]:
    n_draws = int(params.get("draws", 40000))
    buffer_len = int(params.get("buffer_len", 16))
    if not (1 <= n_draws <= 2_000_000):
        raise ExperimentError("draws must be within 1..2,000,000")
    if not (1 <= buffer_len <= 512):
        raise ExperimentError("buffer_len must be within 1..512")
    # Seeds drawn from full uint32 space via OS CSPRNG to simulate random_device
    seed_bytes = secure_bytes(n_draws * 4)
    seeds = [int.from_bytes(seed_bytes[i:i+4], "big") for i in range(0, len(seed_bytes), 4)]
    stats = model_effective_state_space(seeds, buffer_len)
    # deterministic control: same seed twice → identical buffer
    s = seeds[0]
    determinism_ok = model_random_buffer_seeded(s, buffer_len) == model_random_buffer_seeded(s, buffer_len)
    results = {
        **stats,
        "same_seed_same_output": determinism_ok,
        "birthday_expectation_collisions": round(
            (stats["unique_seeds"] ** 2) / (2 * 2**32), 3),
    }
    limitations = [
        "This is a Python MODEL of the C++ mt19937 seeding pattern, not a run of the historical WASM binary.",
        "Collision counts here measure seed-space collapse (2^32), not mnemonic-level statistics directly.",
    ]
    prov = "Synthetic model; algorithm mirrors wasm/src/Random.cpp@69b2da98 line-for-line (see docs/rng-technical-analysis.md)."
    return results, limitations, prov


def exp_modelling_stats_deception(params: dict[str, Any]) -> tuple[dict[str, Any], list[str], str]:
    """Show that statistical uniformity tests PASS on low-entropy-seeded MT output."""
    n_bytes = int(params.get("bytes", 20000))
    if not (1000 <= n_bytes <= 5_000_000):
        raise ExperimentError("bytes must be within 1000..5,000,000")
    seed = int.from_bytes(secure_bytes(4), "big")
    stream = model_random_buffer_seeded(seed, n_bytes)
    tests = run_all_tests(list(stream))
    ent = entropy_estimate(list(stream))
    results = {
        "seeded_with_bits": 32,
        "stream_length": n_bytes,
        "shannon_entropy_bits_per_byte": round(ent, 4),
        "statistical_tests": [
            {"name": t.name, "passed": t.passed,
             "statistic": round(t.statistic, 4),
             "p_value": round(t.p_value, 5) if t.p_value is not None else None}
            for t in tests
        ],
        "all_statistical_tests_pass": all(t.passed for t in tests),
        "effective_key_entropy_bits": 32,
    }
    limitations = [
        "Passing statistical tests does NOT imply cryptographic security — this experiment demonstrates exactly that gap.",
        "MODEL output, not historical binary output.",
    ]
    prov = "Synthetic model of vulnerable per-seed MT19937 stream."
    return results, limitations, prov


# ---------------------------------------------------------------------------
# C. security-fix experiments
# ---------------------------------------------------------------------------

def exp_secure_rng(params: dict[str, Any]) -> tuple[dict[str, Any], list[str], str]:
    n = int(params.get("samples", 20000))
    if not (1000 <= n <= 5_000_000):
        raise ExperimentError("samples must be within 1000..5,000,000")
    a = secure_bytes(n)
    b = secure_bytes(n)
    distinct = a != b
    tests = run_all_tests(list(a))
    results = {
        "provider": "secrets.token_bytes (OS CSPRNG)",
        "length": n,
        "two_draws_differ": distinct,
        "shannon_entropy_bits_per_byte": round(entropy_estimate(list(a)), 4),
        "statistical_tests": [
            {"name": t.name, "passed": t.passed,
             "statistic": round(t.statistic, 4),
             "p_value": round(t.p_value, 5) if t.p_value is not None else None}
            for t in tests
        ],
    }
    limitations = [
        "Statistical tests are necessary-but-not-sufficient evidence for CSPRNG quality.",
        "Behaviour of the actual patched WASM build inside a browser was not exercised; see node_bridge test below when available.",
    ]
    prov = "Real OS CSPRNG via Python secrets module."
    return results, limitations, prov


_NODE_BRIDGE_SNIPPET = r"""
// Faithful transcription of the JS side of wasm/src/Random.cpp@d3c2eee16b15
// (the fixed version's EM_ASM block), used to verify the fallback logic works
// under Node.js. Deterministic-free: prints two random uint32 values.
let getRandomValue;
try {
  const window_ = 'object' === typeof window ? window : self;
  const crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto : window_.msCrypto;
  const f = function() { const buf = new Uint32Array(1); crypto_.getRandomValues(buf); return buf[0] >>> 0; };
  f(); getRandomValue = f;
} catch (e) {
  try {
    const crypto = require('crypto');
    const g = function() { const buf = crypto['randomBytes'](4); return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0; };
    g(); getRandomValue = g;
  } catch (e2) { throw 'No secure random number generator found'; }
}
const x = getRandomValue(), y = getRandomValue();
console.log(JSON.stringify({x, y, differ: x !== y, uint32: x >= 0 && x <= 0xFFFFFFFF}));
"""


def exp_node_bridge(params: dict[str, Any]) -> tuple[dict[str, Any], list[str], str]:
    """Run the fixed version's JavaScript RNG logic under Node.js (if present)."""
    import shutil
    node = shutil.which("node")
    if not node:
        raise ExperimentError("node executable not found — skipping real-JS check")
    p = Path(params.get("out", "/tmp/rng_bridge_check.js"))
    p.write_text(_NODE_BRIDGE_SNIPPET, encoding="utf-8")
    proc = subprocess.run([node, str(p)], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise ExperimentError(f"node exited {proc.returncode}: {proc.stderr[:400]}")
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    results = {
        "node_version": subprocess.run([node, "--version"], capture_output=True,
                                       text=True).stdout.strip(),
        "bridge_ran": True,
        "two_values_differ": data["differ"],
        "uint32_range_ok": data["uint32"],
    }
    limitations = [
        "Transcribes the JS logic of the patch; does not execute the compiled WASM itself.",
    ]
    prov = "Snippet transcribed from fixtures/source-snapshots/Random.cpp@d3c2eee16b15.txt (EM_ASM block)."
    return results, limitations, prov


# ---------------------------------------------------------------------------
# Registry / execution
# ---------------------------------------------------------------------------

_EXPERIMENTS: dict[str, dict[str, Any]] = {
    "E1-source-snapshot-analysis": {
        "category": "real-evidence", "fn": exp_real_evidence,
        "description": "Static analysis of byte-exact vulnerable/fixed upstream snapshots",
    },
    "E2-modelling-seed-collapse": {
        "category": "modelling", "fn": exp_modelling_seed_collapse,
        "description": "Model: 32-bit seed space collapses reachable buffers (birthday collisions)",
    },
    "E3-modelling-stats-deception": {
        "category": "modelling", "fn": exp_modelling_stats_deception,
        "description": "Model: statistical tests pass despite 32-bit effective entropy",
    },
    "E4-secure-rng-properties": {
        "category": "security-fix", "fn": exp_secure_rng,
        "description": "OS CSPRNG behaviour + statistical properties",
    },
    "E5-node-bridge-check": {
        "category": "security-fix", "fn": exp_node_bridge,
        "description": "Runs the patched JS RNG logic under Node.js (optional; needs node)",
    },
}


def list_experiments() -> dict[str, dict[str, Any]]:
    return {k: {"category": v["category"], "description": v["description"]}
            for k, v in _EXPERIMENTS.items()}


def run_experiment(experiment_id: str, params: dict[str, Any] | None = None) -> ExperimentRun:
    if experiment_id not in _EXPERIMENTS:
        raise ExperimentError(
            f"unknown experiment '{experiment_id}'. Available: {sorted(_EXPERIMENTS)}")
    spec = _EXPERIMENTS[experiment_id]
    params = dict(params or {})
    started = utc_now_iso()
    results, limitations, prov = spec["fn"](params)
    run = ExperimentRun(
        run_id=f"{experiment_id}-{uuid.uuid4().hex[:8]}",
        experiment_id=experiment_id,
        category=spec["category"],
        started_at=started,
        finished_at=utc_now_iso(),
        tool_version=__version__,
        python_version=platform.python_version(),
        parameters=params,
        results=results,
        limitations=limitations,
        provenance_note=prov,
    )
    return run


def run_suite(config_path: str | Path, out_dir: str | Path) -> list[ExperimentRun]:
    """Run all experiments enabled in config; write JSON artifacts per run."""
    cfg_p = Path(config_path)
    if not cfg_p.exists():
        raise ExperimentError(f"config file not found: {cfg_p}")
    cfg = json.loads(cfg_p.read_text(encoding="utf-8"))
    experiments_cfg = cfg.get("experiments")
    if not isinstance(experiments_cfg, dict):
        raise ExperimentError("config must contain an 'experiments' object")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    runs: list[ExperimentRun] = []
    for exp_id, opts in experiments_cfg.items():
        if not opts.get("enabled", True):
            continue
        try:
            run = run_experiment(exp_id, opts.get("params", {}))
        except ExperimentError as e:
            # record skipped-with-reason runs instead of failing the suite
            run = ExperimentRun(
                run_id=f"{exp_id}-skipped-{uuid.uuid4().hex[:8]}",
                experiment_id=exp_id,
                category=_EXPERIMENTS.get(exp_id, {}).get("category", "unknown"),
                started_at=utc_now_iso(), finished_at=utc_now_iso(),
                tool_version=__version__, python_version=platform.python_version(),
                parameters=opts.get("params", {}),
                results={"skipped": True, "reason": str(e)},
                limitations=["experiment did not execute"],
            )
        runs.append(run)
        artifact = out / f"{run.run_id}.json"
        artifact.write_text(json.dumps(run.to_dict(), indent=2, ensure_ascii=False),
                            encoding="utf-8")
    return runs
