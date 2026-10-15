"""Complete BIP-39 (English) with full 12-word support + partial phrases.

Functions:
  * entropy -> mnemonic (12/15/18/21/24 words; 12-word = 128-bit entropy)
  * checksum validation via SHA-256 (hashlib, and the numpy vector path from
    sha256_vec.py for bulk filtering of millions of candidate buffers)
  * mnemonic -> seed via PBKDF2-HMAC-SHA512 (2048 rounds, salt "mnemonic"+pass)
  * 11-known + 1-unknown word support: enumerate all 2048 candidates for the
    missing position (checksum filters them down to ~1 valid completion),
    and arbitrary missing-position patterns ("word indexes" list).

Spec recap (BIP-39):
  ENT = bits of entropy (128..256, multiple of 32)
  CS  = ENT/32 checksum bits = first CS bits of SHA256(entropy)
  sequence = ENT||CS split into (ENT+CS)/11 words, each an index in the
  2048-word English list.
"""
from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from typing import Iterable, List, Optional, Sequence, Tuple

import numpy as np

WORDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "bip39-english.txt")


@lru_cache(maxsize=1)
def wordlist() -> Tuple[str, ...]:
    with open(WORDS_FILE, "r", encoding="utf-8") as f:
        words = tuple(w.strip() for w in f if w.strip())
    assert len(words) == 2048, f"corrupt wordlist: {len(words)} words"
    return words


@lru_cache(maxsize=1)
def word_index() -> dict:
    return {w: i for i, w in enumerate(wordlist())}


# ------------------------------------------------------------------ encode
def entropy_to_mnemonic(entropy: bytes) -> str:
    """Canonical BIP-39: 16 bytes -> 12 words (works for 128..256-bit)."""
    ent_bits = len(entropy) * 8
    if ent_bits % 32 or not (128 <= ent_bits <= 256):
        raise ValueError("entropy must be 128..256 bits, multiple of 32")
    cs_bits = ent_bits // 32
    h = hashlib.sha256(entropy).digest()
    val = int.from_bytes(entropy, "big") << cs_bits
    val |= _checksum_bits(h, cs_bits)
    nwords = (ent_bits + cs_bits) // 11
    wl = wordlist()
    out = []
    for i in range(nwords):
        shift = (nwords - 1 - i) * 11
        out.append(wl[(val >> shift) & 0x7FF])
    return " ".join(out)


def _checksum_bits(h: bytes, cs_bits: int) -> int:
    v = 0
    for b in range(cs_bits):
        v = (v << 1) | ((h[b // 8] >> (7 - b % 8)) & 1)
    return v


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Decode + verify checksum; raises ValueError when invalid."""
    idxs = [word_index()[w] for w in mnemonic.lower().split()]
    if len(idxs) not in (12, 15, 18, 21, 24):
        raise ValueError("bad word count")
    val = 0
    for i in idxs:
        val = (val << 11) | i
    total = len(idxs) * 11
    ent_bits = total * 32 // 33
    cs_bits = total - ent_bits
    entropy = (val >> cs_bits).to_bytes(ent_bits // 8, "big")
    h = hashlib.sha256(entropy).digest()
    got = _checksum_bits(h, cs_bits)
    if (val & ((1 << cs_bits) - 1)) != got:
        raise ValueError("BIP-39 checksum mismatch")
    return entropy


def validate_mnemonic(mnemonic: str) -> bool:
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------- seed
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    norm = " ".join(mnemonic.lower().split())
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", norm.encode("utf-8"), salt, 2048, 64)


# ------------------------------------------------------- partial / recovery
def completions_from_11_words(words: Sequence[str],
                              missing_pos: int = 11) -> List[str]:
    """All 12-word mnemonics consistent with 11 known words at `missing_pos`.

    The BIP-39 checksum keeps ~2048/16 = 128 candidates... exactly 2^(11-cs)
    = 128 valid completions for 12-word phrases — every one maps to a valid
    entropy, so ALL are returned for address sweeping.
    """
    if len(words) != 11:
        raise ValueError("need exactly 11 known words")
    if not (0 <= missing_pos < 12):
        raise ValueError("missing_pos must be 0..11")
    wl = wordlist()
    known = list(words)
    out: List[str] = []
    for cand in wl:
        trial = known[:missing_pos] + [cand] + known[missing_pos:]
        try:
            mnemonic_to_entropy(" ".join(trial))
        except Exception:
            continue
        out.append(cand)
    return out


def recover_missing_word(known: Sequence[str], missing_positions: Sequence[int],
                         ) -> List[Tuple[int, str]]:
    """General 'N known + M unknown' recovery over given positions.

    Returns list of (position, word) for EVERY checksum-valid completion
    (searches 2048^M space only when M==1 by design; M>=2 callers should use
    the vectorized bulk filter instead).
    """
    if len(missing_positions) != 1:
        raise NotImplementedError("bulk multi-gap search lives in the engine")
    pos = missing_positions[0]
    kept = [w for i, w in enumerate(known) if i != pos]
    res = []
    for cand in completions_from_11_words(kept, pos):
        res.append((pos, cand))
    return res


# ------------------------------------------------------------- vector filter
def batch_checksum_ok(entropies: "np.ndarray") -> "np.ndarray":
    """Bulk BIP-39 checksum filter over (N,16) uint8 entropy rows.

    A 12-word phrase is valid iff its 128 entropy bits plus the first 4 bits
    of SHA256(entropy) form 12×11-bit indices — which is ALWAYS true for any
    16-byte buffer once we CONSTRUCT the mnemonic.  The real use here is the
    scanner's pre-filter for *pattern-constrained* candidates (e.g. JSBN byte
    streams where only part of the buffer is RNG output): rows whose derived
    12th word must fall inside a restricted subset.  We expose the raw tool:
    returns the first digest byte per row using the vectorized SHA-256
    (self-tested against hashlib on first call).
    """
    from sha256_vec import sha_first_byte_rows
    entropies = np.ascontiguousarray(entropies, dtype=np.uint8)
    return sha_first_byte_rows(entropies)


def entropy_to_indices(entropy: bytes) -> List[int]:
    """The 12 eleven-bit indices of a 12-word phrase (for gap math)."""
    h = hashlib.sha256(entropy).digest()
    val = (int.from_bytes(entropy, "big") << 4) | (h[0] >> 4)
    return [(val >> (11 * (11 - i))) & 0x7FF for i in range(12)]
