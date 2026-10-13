"""rng_research — independent research lab for the historical Trust Wallet
Wallet-Core WASM RNG vulnerability (CVE-2023-31290 / GHSA-pm4f-pggw-8jwc).

This package is a research/verification toolkit. It contains:
  * an evidence ledger with provenance tracking,
  * static analysis of real upstream source snapshots,
  * patch comparison utilities,
  * modelling experiments (synthetic PRNG vs. CSPRNG),
  * statistical property tests (explicitly NOT cryptographic proofs),
  * report generation (Markdown + JSON).
"""

__version__ = "1.0.0"
TOOL_NAME = "rng_research"
