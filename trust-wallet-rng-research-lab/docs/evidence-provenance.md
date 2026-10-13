# Evidence & Provenance System

## Files
- `config/evidence_ledger.json` — 12 claims, each with source, locator, method,
  status ∈ {confirmed, partially_confirmed, needs_more_access}, confidence, notes.
  Loaded/validated by `src/rng_research/evidence.py` (schema-checked; malformed
  entries raise — covered by tests/test_evidence.py).
- `fixtures/source-snapshots/provenance.json` — per-file origin record for the two byte-exact
  snapshots: upstream URL, commit, fetch date (2026-10-12), sha256, license note.
- `fixtures/source-snapshots/GHSA-pm4f-pggw-8jwc.json` — verbatim advisory JSON.
- `fixtures/patches/d3c2eee16b15.diff` — locally generated unified diff between
  the two snapshots (derivative artifact, clearly labelled as such).
- `fixtures/references/` (added U2) — external-oracle program + emitted vectors
  with embedded SHA-256 provenance chain.

## Invariants enforced by tests
1. Snapshot bytes == provenance hashes (raw bytes, no newline normalisation).
2. Ledger statuses never upgraded without new evidence (manual review rule;
   tests assert current statuses to catch silent edits).
3. `.gitattributes` pins `eol=lf` for snapshot files → Windows checkouts stay
   byte-identical (verified via `git check-attr eol`).

## Known provenance gaps
- Emscripten random_device runtime behaviour (ledger #6, needs_more_access).
- Which std::library the shipped WASM used (docs/rng-conformance.md UNVERIFIED list).
- mnemonic-layer consumption code path (docs/entropy-path-analysis.md Step 3 GAP).
