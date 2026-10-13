# Entropy Path: seed → RNG → bytes → mnemonic (U3)

Scope rule: every step below is labelled PROVEN (code+snapshot evidence),
INFERRED (arithmetic/logical consequence of proven facts), or GAP (no evidence
in repo; not resolved). No real wallet data is used anywhere; experiments use
synthetic seeds only.

## Step 0 — entropy source: std::random_device{}()
PROVEN (text): vulnerable snapshot lines 15 & 20 construct `std::random_device`
and draw ONE value per call (`Random.cpp@69b2da9826df.txt`).
GAP: how many bits that draw actually carried at runtime in the shipped WASM
(Emscripten implementations historically returned 32-bit values; the affected
builds' actual generator is ledger #6 = needs_more_access). We therefore treat
"one uint32 word consumed as seed" as the proven part and "its true entropy" as
bounded above by 32 bits — never claimed equal to 32.

## Step 1 — seed → state (MT19937 scalar init)
PROVEN (verified this repo): libstdc++ `mt19937(seed)` maps the uint32 through
`init_genrand`: mt[0]=seed, mt[i]=1812433253*(mt[i-1]^(mt[i-1]>>30))+i mod 2^32.
Verified bit-exactly against the external oracle (docs/rng-conformance.md §Verified 1).
Consequence (INFERRED, elementary): distinct initial states ≤ 2^32. State size
(19937 bits) does NOT enlarge the reachable set; it is fully determined by the seed.

## Step 2 — state → outputs
PROVEN: twist + tempering per Matsumoto–Nishimura; first output after seeding
reproduced exactly by our independent engine.
PROVEN (snapshot line 21): consumption is `rng() & 0x000000ff` — one byte per
32-bit draw; 24 high bits discarded per draw. For a 16-byte buffer, 16 draws
from ONE engine instance are used before the instance dies (per-call reseed).

## Step 3 — bytes → mnemonic
GAP (repository evidence stops here): wallet-core's mnemonic layer lives outside
`wasm/src/Random.cpp`. Ledger #5 says random_buffer fed ~16 entropy bytes into
mnemonic generation; the consuming code path (which API called random_buffer,
how many times per wallet creation) was NOT snapshotted in this repo. Therefore:
- INFERRED bound: each 16-byte buffer has ≤ 2^32 possible values (seed-bounded).
- If exactly ONE such buffer produced the BIP-39 entropy, mnemonic entropy ≤ 32
  bits — consistent with advisory framing but end-to-end enumeration was never
  executed here (ledger #5 explicitly marks partially_confirmed).
- Multi-buffer note: because EVERY call reseeds independently, k buffers carry
  at most 32k bits of seed entropy total — still far below BIP-39's 128/256-bit
  design when k ≤ 8 (typical); exact k is a GAP.

## Distinctions enforced
- algorithm state space (19937 bits) ≠ seed width (32) ≠ realized entropy (≤32, possibly less — GAP).
- statistical uniformity of model streams (E2/E3 results) ≠ unpredictability.
- Model numbers (CPython convention) ≠ historical binary numbers (see conformance doc).

## Safety statement
This analysis quantifies a historical weakness for defensive understanding. It
deliberately provides no attack tooling: no address scanning, no key recovery,
no real-data processing. Experiments operate on synthetic seeds in-process.
