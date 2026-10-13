"""Trust Wallet vulnerable-RNG wallet model (exact pipeline, no mocks).

seed(uint32) -> std::mt19937 scalar-seeded stream -> random_buffer low bytes
             -> BIP-39 entropy -> mnemonic -> BIP-39 seed -> BIP-32/BIP-44 ETH address.

The MT19937 core is the lab's reference engine, conformance-verified bit-for-bit
against an external libstdc++ oracle (fixtures/references/mt19937_scalar_vectors.txt).
"""
from __future__ import annotations

import hashlib
from functools import lru_cache

from mt19937_reference import MT19937Reference
from bip39 import entropy_to_mnemonic, mnemonic_to_seed
from hd import derive_path, eth_address

ENTROPY_LEN = 16  # Trust Wallet browser extension generated 12-word wallets


def vulnerable_random_buffer(seed: int, length: int = ENTROPY_LEN) -> bytes:
    """Model of wasm/src/Random.cpp@69b2da98: one uint32 seed, low byte per call."""
    engine = MT19937Reference()
    engine.seed_scalar(seed & 0xFFFFFFFF)
    return bytes(engine.next_uint32() & 0xFF for _ in range(length))


@lru_cache(maxsize=200_000)
def checksum_passes(seed: int) -> bool:
    """Cheap pre-filter: BIP-39 checksum word must be a multiple of 16."""
    ent = vulnerable_random_buffer(seed)
    return hashlib.sha256(ent).digest()[0] % 16 == 0


@lru_cache(maxsize=20_000)
def wallet_for_seed(seed: int) -> tuple[str, str]:
    """Return (mnemonic, eth_address) for a uint32 seed under the vulnerable model."""
    mnemonic = entropy_to_mnemonic(vulnerable_random_buffer(seed))
    key, _ = derive_path(mnemonic_to_seed(mnemonic), "m/44'/60'/0'/0/0")
    return mnemonic, eth_address(key)
