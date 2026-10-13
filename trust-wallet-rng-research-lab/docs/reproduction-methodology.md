# Reproduction Methodology

## Environment requirements
- Python ≥ 3.10 (developed/verified on CPython 3.12, Linux x86_64; Windows
  supported — paths are `pathlib`-based, tests avoid OS-specific assumptions).
- Dev deps: `pip install -e ".[dev]"` or `pip install -r requirements-dev.txt`
  (pytest only). No network access needed for tests.
- Optional (conformance oracle regeneration): any C++11 compiler, e.g. g++.

## Run everything
```bash
cd trust-wallet-rng-research-lab
python -m pytest tests/            # full suite incl. MT19937 conformance
python -m rng_research.cli check-environment
python -m rng_research.cli evidence --all
python -m rng_research.cli analyze-source
python -m rng_research.cli compare
python -m rng_research.cli run-experiments   # writes artifacts/ + reports/
```

## Integrity checks performed by the suite
- `tests/test_provenance.py`: raw-byte SHA-256 of both snapshots vs
  `fixtures/source-snapshots/provenance.json` (newline-sensitive; `.gitattributes` pins LF so a
  fresh Windows checkout keeps identical bytes).
- `tests/test_patch_analysis.py`: recorded diff reproduces snapshot→snapshot.
- `tests/test_mt19937_conformance.py`: reference engine vs external libstdc++
  vectors; vector file itself is re-parsed (not trusted blindly).

## Regenerating the MT19937 oracle vectors (independent verification)
```bash
g++ -O2 -std=c++11 fixtures/references/gen_mt.cpp -o /tmp/gen_mt
/tmp/gen_mt    # compare against fixtures/references/mt19937_scalar_vectors.txt
sha256sum fixtures/references/*.{cpp,txt}   # must match hashes in mt19937_reference.py docstring
```
Note: values depend on the standard library's mt19937 seeding contract;
results from MSVC/libc++ may differ legitimately (documented in
docs/rng-conformance.md).

## Experiment artifact traceability
Each run records run_id, timestamp, config, and environment capture
(`experiment_runner.py` + `environment.py`) into `artifacts/`; reports link
artifact filenames (`report_generator.py`). Re-running with the same seeds is
bit-deterministic for model experiments (synthetic seeds only).
