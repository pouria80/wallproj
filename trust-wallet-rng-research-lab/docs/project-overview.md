# Project Overview — Trust Wallet RNG Research Lab

## Purpose
Independent, reproducible research lab investigating the historical RNG
vulnerability in the Trust Wallet Browser Extension (CVE-2023-31290 /
GHSA-pm4f-pggw-8jwc), affecting wallet-core < 3.1.1 as used by extension
versions 0.0.172–0.0.182. Defense-oriented research only: source analysis,
patch comparison, seed-space modeling with synthetic data, and secure-RNG
validation. No operational tooling for attacking real wallets is provided or
intended.

## Architecture (actual modules)
| Layer | Module(s) | Role |
|---|---|---|
| Historical Reference | `fixtures/source-snapshots/`, `fixtures/source-snapshots/provenance.json` | Byte-exact upstream files at commits `69b2da9826df` (vulnerable) and `d3c2eee16b15` (fixed); SHA-256 verified by `tests/test_provenance.py` |
| Evidence | `src/rng_research/evidence.py`, `config/evidence_ledger.json` | Claim→source ledger with status taxonomy (confirmed / partially_confirmed / needs_more_access) |
| Source & patch analysis | `source_analysis.py`, `patch_analysis.py` | Static analysis of snapshots; unified-diff comparison (`fixtures/patches/d3c2eee16b15.diff`) |
| Historical Behavior (MODEL) | `secure_rng.py` (`model_*` functions) | Clearly-labelled Python model of the vulnerable per-call-reseed pattern. **Not** bit-equivalent to the historical binary — see `docs/rng-conformance.md` |
| RNG Conformance | `mt19937_reference.py`, `tests/test_mt19937_conformance.py`, `fixtures/references/` | Independent MT19937 engine verified against an external libstdc++ oracle |
| Statistical validation | `rng_properties.py` | Monobit, serial-correlation, chi-square, poker, runs tests + battery; explicitly NOT a proof of cryptographic security |
| Experiment framework | `experiment_runner.py`, `config/experiments.json` | E1–E5 suites (real-evidence / modelling / secure-fix categories), run-id + settings recorded in artifacts |
| Reporting | `report_generator.py`, `reports/` | Markdown + JSON reports traceable to run ids |
| Environment | `environment.py`, `cli.py` | `check-environment`, cross-platform path handling |

## Entry points
- CLI: `python -m rng_research.cli {info|analyze-source|compare|evidence|run-tests|run-experiments|report|check-environment}`
- Tests: `python -m pytest tests/` (offline; no network required)

## Provenance of this documentation set
Every claim here is backed by files inside this repository or by entries in
`config/evidence_ledger.json`. Where evidence ends, `docs/limitations.md`
records the gap. Documents were written from actual repo/code inspection on
2026-10-13; nothing was copied from secondary reporting without a ledger entry.
