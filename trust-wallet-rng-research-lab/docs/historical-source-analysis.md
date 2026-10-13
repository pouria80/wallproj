# Historical Source Analysis (CVE-2023-31290)

All statements below cite local artifacts; ledger references are row indices of
`config/evidence_ledger.json`.

## Vulnerable snapshot (ledger #1, confirmed)
File: `fixtures/source-snapshots/Random.cpp@69b2da9826df.txt`
SHA-256: `f8dea1b9bd1e7057a0f7166ef372e3b34fc4a96eb7fa9e31bbd137beb8c5aab1`
Upstream path: `wasm/src/Random.cpp` @ commit `69b2da9826dfdeb8116be1e5a3747b3e9418592d`
(lines 13–21):

```cpp
uint32_t random32(void) {
    std::mt19937 rng(std::random_device{}());      // fresh engine, ONE uint32 seed
    return rng();                                   // first output only
}
void random_buffer(uint8_t* buf, size_t len) {
    std::mt19937 rng(std::random_device{}());       // reseeded PER CALL
    std::generate_n(buf, len, [&rng]() -> uint8_t { return rng() & 0x000000ff; });
}
```

Key structural facts read directly from the file:
1. Engine construction happens inside each call → state never reused across calls.
2. Seed material = one value returned by `std::random_device{}()`; MT19937
   scalar seeding consumes exactly one 32-bit word (libstdc++ `init_genrand`).
3. `random_buffer` truncates each 32-bit output to its low 8 bits (`& 0xff`),
   discarding 24 bits per draw.

## Fixed snapshot (ledger #2/#8, confirmed)
File: `fixtures/source-snapshots/Random.cpp@d3c2eee16b15.txt`
SHA-256: `609bb7543f9d0d1200f7e62c69c428e805b5e2b4600ece2e60656216ae7f096f`
Commit `d3c2eee16b154cbb69e8959b01e5e71fbabb1212` ("[emscripten]: use javascript
for random generation (#2750)", parent = 69b2da9826df…, single-file change).
Replaces `<random>` usage with EM_ASM bridges:
browser `crypto.getRandomValues` → Node `require('crypto').randomBytes(4)` →
hard failure (`throw 'No secure random number generator found'`). Fails closed.

Diff artifact: `fixtures/patches/d3c2eee16b15.diff` (generated locally from the
two byte-exact snapshots; verified by `tests/test_patch_analysis.py`).

## Version mapping (ledger #0/#3, confirmed)
Advisory JSON saved verbatim at `fixtures/source-snapshots/GHSA-pm4f-pggw-8jwc.json`:
wallet-core < 3.1.1; extension 0.0.172–0.0.182; fix commit tagged 3.1.1.

## What we did NOT verify
- We never compiled/executed the historical WASM binary (see docs/limitations.md).
- The exact runtime behaviour of Emscripten's `std::random_device` in the
  affected builds is ledger #6 = `needs_more_access` (secondary reports suggest
  weak/deterministic behaviour; not independently reproduced here).
