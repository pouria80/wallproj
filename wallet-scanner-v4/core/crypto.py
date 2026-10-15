"""BIP-39 (entropy -> mnemonic -> seed) + BIP-32/BIP-44 HD derivation.

Pure stdlib (hashlib/hmac/struct) + our own ecc.py — no external C deps.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from functools import lru_cache
from pathlib import Path

from ecc import eth_address as _ecc_eth_address  # re-exported below

_WORDLIST_PATH = Path(__file__).resolve().parent / "bip39-english.txt"


# ============================================================ BIP-39
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
    return " ".join(words[(num >> (bits + cs - 11 * (i + 1))) & 0x7FF]
                    for i in range((bits + cs) // 11))


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    import unicodedata
    norm = unicodedata.normalize("NFKD", mnemonic)
    return hashlib.pbkdf2_hmac("sha512", norm.encode(),
                               ("mnemonic" + passphrase).encode(), 2048, 64)


# ============================================================ BIP-32
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HMAC_KEY = b"Bitcoin seed"


def _ser2p(i: int) -> bytes:
    return b"\x00" + struct.pack(">I", i)


def _compressed_pub(priv: bytes) -> bytes:
    """SEC compressed public key, computed with pure-Python ecc."""
    from ecc import point_mul
    k = int.from_bytes(priv, "big")
    x, y = point_mul(k)  # type: ignore[misc]
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()


def master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    i = hmac_sha512(HMAC_KEY, seed)
    k, cc = i[:32], i[32:]
    n = int.from_bytes(k, "big")
    if n == 0 or n >= CURVE_ORDER:
        raise ValueError("invalid master key (astronomically unlikely)")
    return k, cc


def _ckd_priv(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = key + struct.pack(">I", index)
    else:
        data = _compressed_pub(key) + struct.pack(">I", index)
    i = hmac_sha512(chain_code, data)
    il, ir = i[:32], i[32:]
    k = (int.from_bytes(il, "big") + int.from_bytes(key, "big")) % CURVE_ORDER
    if k == 0 or k >= CURVE_ORDER:
        raise ValueError("invalid derived key")
    return k.to_bytes(32, "big"), ir


def derive_path(seed: bytes, path: str) -> tuple[bytes, bytes]:
    key, cc = master_from_seed(seed)
    parts = path.replace("m/", "").split("/")
    for p in parts:
        hardened = p.endswith("'")
        idx = int(p[:-1]) + 0x80000000 if hardened else int(p)
        key, cc = _ckd_priv(key, cc, idx)
    return key, cc


def eth_address(priv: bytes) -> str:
    return _ecc_eth_address(priv)
