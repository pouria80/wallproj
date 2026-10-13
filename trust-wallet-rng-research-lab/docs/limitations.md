# Limitations, Open Questions & Reconstruction Deviations

## Historical reconstruction deviations (by design, documented)
1. **Model ≠ binary.** `secure_rng.model_*` reproduces the vulnerable
   architecture (per-call fresh MT19937, one uint32 seed, low-byte truncation)
   but uses CPython's seeding convention. Bit-level equality with the shipped
   WASM build is UNVERIFIED (see docs/rng-conformance.md). Seed-space-collapse
   conclusions (≤2^32 per buffer) are robust to this difference.
2. **No WASM rebuild.** We deliberately did not compile or substitute any
   historical artefact: the original Emscripten toolchain version for the
   affected extension builds is unknown here, and rebuilding would create a
   non-historical artefact that could be mistaken for the original. Layer kept
   documentation-only and extensible.
3. **random_buffer call count k per wallet creation** is not pinned by repo
   evidence (entropy doc Step 3 GAP).

## Statistical analysis limits
- Passing monobit/poker/runs tests demonstrates uniformity only; explicitly NOT
  unpredictability (ledger #10). Thresholds use df = m−1 poker convention
  (corrected in earlier commits; guarded by tests).
- Collision experiment (E3) measures modelled seed collapse, not real-world
  mnemonic collisions.

## Unresolved questions (tracked)
| # | Question | Needed to resolve |
|---|---|---|
| L1 | Entropy actually delivered by Emscripten `std::random_device` in affected builds | Historical WASM binary or Emscripten-version-pinned reproduction (ledger #6) |
| L2 | Standard library used in released WASM (libstdc++ vs libc++) | Build metadata of release 0.0.172–0.0.182 |
| L3 | Exact number/size of random_buffer calls per mnemonic | wallet-core mnemonic-layer snapshot |
| L4 | init_by_array bit-level validation | external oracle run (gen_mt-style) once array-seeding relevance is established |

## Safety scope reminders
Synthetic data only; no key recovery tooling; no scanning of real addresses;
no network operations inside tests. This lab's outputs must not be read as
instructions for exploiting live wallets — they quantify a patched historical
defect for defensive research.
