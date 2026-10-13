"""Patch / version comparison utilities.

Compares two local text snapshots with `difflib` (no external patch tooling),
produces unified diffs, statistics and a semantic summary of the RNG-relevant
changes. Also validates that a stored .diff file matches the diff recomputed
from its two source snapshots (integrity check for fixtures).
"""
from __future__ import annotations

import difflib
from pathlib import Path

from .models import DiffStats, PatchComparison


class PatchError(Exception):
    """Raised on missing inputs or malformed patch data."""


def _read_lines(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise PatchError(f"file not found: {p}")
    try:
        return p.read_text(encoding="utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as e:
        raise PatchError(f"not valid UTF-8 text: {p}") from e


def compare_files(path_a: str | Path, path_b: str | Path,
                  label_a: str | None = None, label_b: str | None = None
                  ) -> PatchComparison:
    a_lines = _read_lines(path_a)
    b_lines = _read_lines(path_b)
    diff = list(difflib.unified_diff(a_lines, b_lines,
                                     fromfile=label_a or str(path_a),
                                     tofile=label_b or str(path_b)))
    added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
    hunks = sum(1 for l in diff if l.startswith("@@"))
    identical = not diff
    key_changes = _semantic_key_changes("".join(diff))
    return PatchComparison(
        file_a=str(path_a), file_b=str(path_b),
        stats=DiffStats(added=added, removed=removed, changed_hunks=hunks,
                        identical=identical),
        unified_diff="".join(diff),
        key_changes=key_changes,
    )


def _semantic_key_changes(diff_text: str) -> list[str]:
    changes: list[str] = []
    if "-#include <random>" in diff_text and "+#include <emscripten.h>" in diff_text:
        changes.append("Replaced C++ <random> header with Emscripten host bridge.")
    if "std::mt19937 rng(std::random_device{}());" in diff_text:
        changes.append("Removed per-call std::mt19937 seeded by std::random_device "
                       "(the 32-bit-seed vulnerability).")
    if "getRandomValues" in diff_text:
        changes.append("Added browser Web Crypto (crypto.getRandomValues) source; "
                       "falls back to window.crypto / msCrypto.")
    if "require('crypto')" in diff_text or "randomBytes" in diff_text:
        changes.append("Added Node.js crypto.randomBytes fallback for non-browser hosts.")
    if "No secure random number generator found" in diff_text:
        changes.append("Fail-closed: throws when no CSPRNG is available instead of "
                       "silently using weak randomness.")
    if "javascript_buf" in diff_text:
        changes.append("random_buffer now draws bytes one-by-one from the JS CSPRNG "
                       "(note: uint32 truncated to uint8 keeps 8 bits per call — "
                       "still CSPRNG-backed, unlike the old mt19937 seeding).")
    if "randombytes_init_if_needed" in diff_text:
        changes.append("One-time lazy initialisation of the JS RNG bridge.")
    return changes


def verify_patch_file(patch_path: str | Path, snapshot_a: str | Path,
                      snapshot_b: str | Path) -> bool:
    """True if *patch_path* content equals the unified diff recomputed from the
    two snapshots (ignoring +++/--- header lines which may carry labels)."""
    stored = Path(patch_path).read_text(encoding="utf-8").splitlines()
    recomputed = "".join(difflib.unified_diff(
        _read_lines(snapshot_a), _read_lines(snapshot_b),
        fromfile="a", tofile="b")).splitlines()

    def body(lines: list[str]) -> list[str]:
        return [l for l in lines if not l.startswith(("+++", "---", "@@", "\\ "))]

    return body(stored) == body(recomputed)
