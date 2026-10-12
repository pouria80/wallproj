"""Static analysis of C++ RNG source snapshots (offline, no execution).

The analyzer recognises the exact vulnerable pattern found upstream in
`wasm/src/Random.cpp` (mt19937 constructed and seeded per call from
`std::random_device`) and the fixed pattern (delegation to JavaScript
Web Crypto / Node crypto via Emscripten `EM_ASM`).

Untrusted input policy: files are read as *text data only*; nothing is
compiled or executed here.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import SourceAnalysisResult, SourceFinding, sha256_file


class SourceAnalysisError(Exception):
    """Raised when a file cannot be analysed (missing, empty, binary...)."""


_MAX_BYTES = 1_000_000  # refuse absurdly large inputs

_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("mt19937", "prng_usage",
     re.compile(r"std::mt19937"),
     "Mersenne Twister PRNG — not a CSPRNG; 19937-bit internal state but "
     "security depends entirely on the seed entropy actually supplied."),
    ("random_device-seed", "prng_usage",
     re.compile(r"std::random_device\s*\{\s*\}\s*\(\s*\)"),
     "Seed drawn from std::random_device. In Emscripten before the fix this "
     "was deterministic/weak at runtime; regardless, mt19937 consumes only a "
     "single uint32 seed value."),
    ("per-call-reseed", "prng_usage",
     re.compile(r"std::mt19937\s+\w+\s*\("),
     "A fresh mt19937 engine is constructed inside each function call: the "
     "output of one call reveals nothing about the next call's seed, but the "
     "entire output space collapses to the set reachable from 32-bit seeds "
     "(≈2^32 distinct mnemonics for a whole wallet generation)."),
    ("js-getRandomValues", "api_call",
     re.compile(r"getRandomValues"),
     "Uses Web Crypto crypto.getRandomValues — browser CSPRNG."),
    ("js-randomBytes", "api_call",
     re.compile(r"randomBytes"),
     "Uses Node.js crypto.randomBytes fallback — OS CSPRNG."),
    ("emscripten-EM_ASM", "api_call",
     re.compile(r"EM_ASM"),
     "Emscripten bridge into the JavaScript host environment for randomness."),
    ("no-secure-fallback", "api_call",
     re.compile(r"No secure random number generator found"),
     "Fail-closed behaviour: throws if neither Web Crypto nor Node crypto is "
     "available, instead of silently using weak randomness."),
]

_FUNC_RE = re.compile(r"^(?:extern\s+\"C\"\s*)?(?:static\s+)?[A-Za-z_][\w:*&<> ]*?\b(\w+)\s*\([^;{]*\)\s*\{?\s*$")
_KNOWN_FUNCS = {"random32", "random_buffer", "javascript_random",
                "javascript_stir", "javascript_buf", "randombytes_init_if_needed"}


def analyze_source_file(path: str | Path) -> SourceAnalysisResult:
    p = Path(path)
    if not p.exists():
        raise SourceAnalysisError(f"source file not found: {p}")
    if p.is_dir():
        raise SourceAnalysisError(f"expected a file, got directory: {p}")
    size = p.stat().st_size
    if size == 0:
        raise SourceAnalysisError(f"source file is empty: {p}")
    if size > _MAX_BYTES:
        raise SourceAnalysisError(f"source file too large (> {_MAX_BYTES} B): {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise SourceAnalysisError(f"source file is not valid UTF-8 text: {p}") from e

    lines = text.splitlines()
    findings: list[SourceFinding] = []
    uses_mt19937 = False
    seeds_rd = False
    reseeds = False
    js_crypto = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for name, kind, rx, interp in _PATTERNS:
            if rx.search(line):
                findings.append(SourceFinding(name=name, kind=kind, line=idx,
                                              snippet=stripped[:160],
                                              interpretation=interp))
                if name == "mt19937":
                    uses_mt19937 = True
                if name == "random_device-seed":
                    seeds_rd = True
                if name == "per-call-reseed":
                    reseeds = True
                if name in ("js-getRandomValues", "js-randomBytes"):
                    js_crypto = True
        for fn in _KNOWN_FUNCS:
            if re.search(rf"\b{fn}\s*\(", line) and ("uint32_t" in line or "void" in line or "static" in line):
                findings.append(SourceFinding(name=fn, kind="function", line=idx,
                                              snippet=stripped[:160],
                                              interpretation="exported/internal RNG entry point"))
                break

    result = SourceAnalysisResult(
        path=str(p), sha256=sha256_file(str(p)), findings=findings,
        uses_mt19937=uses_mt19937, seeds_with_random_device=seeds_rd,
        reseeds_per_call=reseeds, delegates_to_js_crypto=js_crypto,
    )
    if uses_mt19937 and reseeds:
        result.summary = (
            "VULNERABLE PATTERN: every call constructs a new std::mt19937 "
            "seeded with a single 32-bit value. Effective entropy per call is "
            "bounded by the seed space (2^32 states), independent of how good "
            "the seed source appears."
        )
    elif js_crypto:
        result.summary = (
            "FIXED PATTERN: randomness is delegated to the JS host "
            "(crypto.getRandomValues / Node crypto.randomBytes) through "
            "Emscripten EM_ASM, with a fail-closed error when no CSPRNG exists."
        )
    else:
        result.summary = "No recognised RNG pattern found in this snapshot."
    return result


def classify_snapshot(result: SourceAnalysisResult) -> str:
    """Return 'vulnerable', 'fixed' or 'unknown' for an analysis result."""
    if result.uses_mt19937 and result.reseeds_per_call:
        return "vulnerable"
    if result.delegates_to_js_crypto:
        return "fixed"
    return "unknown"
