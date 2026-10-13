# RNG Technical Analysis

## Concepts kept strictly separate
| Concept | Value here | Evidence class |
|---|---|---|
| MT19937 internal state size | 19937 bits (624×32−pad) | algorithm spec (Matsumoto–Nishimura 1998) |
| Seed input width (scalar init) | 32 bits | libstdc++ `init_genrand`; verified streams in `fixtures/references/mt19937_scalar_vectors.txt` |
| Per-call seed entropy bound | ≤ 2^32 distinct engines per `random_buffer` call | direct reading of vulnerable snapshot (line 15/20) |
| Effective mnemonic entropy | claimed ~32 bits by advisory context | ledger #5 = partially_confirmed (inferred, not executed end-to-end) |
| Reachable-state count after scalar init | ≤ 2^32 distinct initial states | bijection argument on init recurrence (state words are deterministic functions of the seed) |

State size ≠ seed entropy: although MT19937 has a huge nominal state space,
scalar initialization maps the single 32-bit seed deterministically into one of
at most 2^32 initial states; per-call reseeding means every buffer drawn lives
inside that collapsed subset. Conversely, observing good statistical uniformity
of outputs does NOT restore the missing seed entropy (demonstrated experimentally
by E3, `experiment_runner.py`, and tested by `tests/test_rng_properties.py`).

## Output consumption detail
`rng() & 0x000000ff` keeps only the low 8 bits of each tempered word. Truncation
of tempered MT19937 outputs still leaks linear relations usable for full state
recovery given ≥624 consecutive bytes from ONE engine (Frieze et al.); however in
the historical bug each call reseeded, so state-recovery attacks are moot — the
binding constraint is the 32-bit seed itself. This distinction is asserted from
the snapshot code, not measured.

## Model vs original (IMPORTANT)
`secure_rng.model_random32` uses CPython's `random.Random(seed, version=2)`.
CPython shares the MT19937 core but NOT the scalar-seeding contract of
libstdc++. Verified difference: `tests/test_mt19937_conformance.py::
test_cpython_seeding_contract_differs_from_libstdcxx`. Therefore all seed→output
numbers produced by the MODEL are architecture-faithful but not bit-faithful to
the historical build. Conclusions about seed-space collapse (≤2^32) hold for
either convention because they depend only on seed width, not stream values.
