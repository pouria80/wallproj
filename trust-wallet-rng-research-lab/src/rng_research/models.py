"""Shared data models for the RNG research lab.

All models are plain dataclasses with explicit validation helpers so that
evidence records, analysis results and experiment runs can be serialized to
JSON reproducibly.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now_iso() -> str:
    """Current UTC timestamp, ISO-8601 with seconds precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class VerificationStatus(str, Enum):
    """Classification of a claim against primary evidence."""
    CONFIRMED = "confirmed"                       # تأییدشده
    PARTIALLY_CONFIRMED = "partially_confirmed"   # تا حدی تأییدشده
    UNCONFIRMED = "unconfirmed"                   # تأییدنشده
    REFUTED = "refuted"                           # ردشده
    NEEDS_ACCESS = "needs_more_access"            # نیازمند دسترسی بیشتر


VALID_STATUSES = {s.value for s in VerificationStatus}

_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{7,12}$")


def is_commit_like(value: str) -> bool:
    return bool(_SHA_RE.match(value))


@dataclass
class EvidenceRecord:
    """One row of the evidence ledger.

    claim:      the technical claim being tracked.
    source:     primary source (URL / repo identifier).
    locator:    file/line or commit reference within the source.
    method:     how the claim was verified (e.g. 'fetched raw file at commit').
    status:     one of VALID_STATUSES.
    confidence: 'high' | 'medium' | 'low'.
    notes:      free text; must state whether verification was direct from
                source or secondary reporting.
    """
    claim: str
    source: str
    locator: str
    method: str
    status: str
    confidence: str = "high"
    notes: str = ""

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.claim.strip():
            errors.append("claim must not be empty")
        if not self.source.strip():
            errors.append("source must not be empty")
        if self.status not in VALID_STATUSES:
            errors.append(f"status '{self.status}' not in {sorted(VALID_STATUSES)}")
        if self.confidence not in {"high", "medium", "low"}:
            errors.append("confidence must be high|medium|low")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvidenceRecord":
        required = {"claim", "source", "locator", "method", "status"}
        missing = required - set(d)
        if missing:
            raise ValueError(f"EvidenceRecord missing fields: {sorted(missing)}")
        return cls(
            claim=d["claim"], source=d["source"], locator=d["locator"],
            method=d["method"], status=d["status"],
            confidence=d.get("confidence", "high"), notes=d.get("notes", ""),
        )


@dataclass
class SourceFinding:
    """A structural finding extracted from a C++ source snapshot."""
    name: str            # e.g. function name
    kind: str            # 'function', 'include', 'prng_usage', 'api_call'
    line: int            # 1-based line number
    snippet: str
    interpretation: str  # what it implies for RNG behaviour


@dataclass
class SourceAnalysisResult:
    path: str
    sha256: str
    findings: list[SourceFinding] = field(default_factory=list)
    uses_mt19937: bool = False
    seeds_with_random_device: bool = False
    reseeds_per_call: bool = False
    delegates_to_js_crypto: bool = False
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "sha256": self.sha256,
            "uses_mt19937": self.uses_mt19937,
            "seeds_with_random_device": self.seeds_with_random_device,
            "reseeds_per_call": self.reseeds_per_call,
            "delegates_to_js_crypto": self.delegates_to_js_crypto,
            "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
        }


@dataclass
class DiffStats:
    added: int
    removed: int
    changed_hunks: int
    identical: bool


@dataclass
class PatchComparison:
    file_a: str
    file_b: str
    stats: DiffStats
    unified_diff: str
    key_changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentRun:
    """Metadata + result payload for one executed experiment."""
    run_id: str
    experiment_id: str
    category: str          # 'real-evidence' | 'modelling' | 'security-fix'
    started_at: str
    finished_at: str
    tool_version: str
    python_version: str
    parameters: dict[str, Any]
    results: dict[str, Any]
    limitations: list[str] = field(default_factory=list)
    provenance_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
