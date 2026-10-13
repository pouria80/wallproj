"""BIP-39 reference implementation (entropy -> mnemonic -> seed)."""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

_WORDLIST_PATH = Path(__file__).resolve().parent / "bip39-english.txt"


@lru_cache(maxsize=1)
def wordlist() -> list[str]:
    words = [w.strip() for w in _WORDLIST_PATH.read_text("utf-8").splitlines() if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"wordlist must have 2048 entries, got {len(words)}")
    return words


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("invalid entropy length")
    bits = len(entropy) * 8
    cs = bits // 32
    num = int.from_bytes(entropy, "big") << cs
    num |= hashlib.sha256(entropy).digest()[0] >> (8 - cs)
    words = wordlist()
    return " ".join(words[(num >> (bits + cs - 11 * (i + 1))) & 0x7FF] for i in range((bits + cs) // 11))


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    import unicodedata
    norm = unicodedata.normalize("NFKD", mnemonic)
    return hashlib.pbkdf2_hmac("sha512", norm.encode(),
                               ("mnemonic" + passphrase).encode(), 2048, 64)
