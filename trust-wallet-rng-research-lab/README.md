# Trust Wallet RNG Research Lab

Reproducible, defense-oriented research lab for the historical RNG
vulnerability of the Trust Wallet Browser Extension
(CVE-2023-31290 / GHSA-pm4f-pggw-8jwc; wallet-core < 3.1.1, extension
0.0.172–0.0.182). Contains byte-exact upstream snapshots (vulnerable + fixed),
an evidence ledger, a clearly-labelled behavioural MODEL of the vulnerable RNG,
an independent MT19937 engine validated against an external libstdc++ oracle,
statistical property tests, and a controlled experiment framework over
synthetic data only.

## Quick start
```bash
pip install -r requirements-dev.txt
python -m pytest tests/
python -m rng_research.cli check-environment
python -m rng_research.cli run-experiments
```

## Documentation
Start at [docs/index.md](docs/index.md). Read
[docs/limitations.md](docs/limitations.md) before quoting any result: it lists
exactly which claims are verified, inferred, or unverified (notably: the Python
model is architecture-faithful but its bit-level equality to the shipped WASM
build is UNVERIFIED).

## Safety
Synthetic data, isolated analysis, no key-recovery or attack tooling.
