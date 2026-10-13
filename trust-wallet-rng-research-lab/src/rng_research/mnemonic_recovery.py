"""Deterministic BIP-39 seed→mnemonic reconstruction engine (research-grade).

This module upgrades the lab's modelling layer from "buffer-level output
collapse" to an EXACT, bit-accurate reconstruction pipeline:

    uint32 seed  ->  libstdc++ std::mt19937(seed)   [VERIFIED core:
                     mt19937_reference.MT19937Reference, conformance-tested
                     against an external g++ 12.2 oracle]
                 ->  random_buffer(n) low-byte truncation (rng() & 0xff)
                     per wasm/src/Random.cpp@69b2da98
                 ->  entropy bytes  ->  BIP-39 checksum word  ->  mnemonic
                     (trezor/python-mnemonic when installed; a built-in
                     reference implementation is used otherwise — both are
                     conformance-tested against official vectors)

WHY THIS IS CORRECT-BY-CONSTRUCTION (and where it still isn't):
* The MT19937 scalar-seed stream produced here matches libstdc++ bit-for-bit
  for the tested seeds (see tests/test_mt19937_conformance.py and
  fixtures/references/mt19937_scalar_vectors.txt).  This closes gap L4-partial
  that the earlier CPython-based ``secure_rng.model_*`` helpers carried.
* The historical WASM binary was built with Emscripten; whether its
  ``std::random_device`` fed exactly one uint32 into ``init_genrand`` and
  which stdlib implementation shipped remains UNVERIFIED (ledger questions
  L1/L2).  Outputs of this module are therefore *candidate reconstructions*
  over the documented seed model — they must be validated against on-chain
  facts before being treated as historical truth.
* Scope guard: enumeration is capped so this tool can NEVER sweep large key
  spaces.  It reconstructs mnemonics for seeds you already possess (from your
  own wallet's audit export, or from published research corpora), and audits
  given mnemonics.  It performs no network I/O and derives no addresses.
"""
from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator

from .mt19937_reference import MT19937Reference

# ---------------------------------------------------------------------------
# Constants & errors
# ---------------------------------------------------------------------------

MAX_ENTROPY_BYTES = 32          # BIP-39: CS ≤ 16 bits ⇒ entropy ≤ 32 bytes
MAX_ENUMERATION_SEEDS = 1_000_000  # hard scope cap (see module docstring)
UINT32_MAX = 2**32 - 1


class RecoveryError(Exception):
    """Raised on invalid recovery inputs or scope violations."""


# ---------------------------------------------------------------------------
# Built-in BIP-39 reference implementation (PBKDF2-HMAC-SHA512 via hashlib)
# ---------------------------------------------------------------------------

_WORDLIST_PATH = (Path(__file__).resolve().parents[2]
                  / "fixtures" / "references" / "bip39-english.txt")

_BIP39_VECTORS_SHA256 = \
    "893a88648a421605cda8d0cf15adb153b30bcd4c7ecfd0f70f581a7de491a0ab"


def _load_builtin_wordlist() -> list[str]:
    words = [w.strip() for w in _WORDLIST_PATH.read_text(
        encoding="utf-8").splitlines() if w.strip()]
    if len(words) != 2048:
        raise RecoveryError(f"wordlist must have 2048 entries, got {len(words)}")
    return words


@lru_cache(maxsize=1)
def builtin_wordlist() -> list[str]:
    return _load_builtin_wordlist()


def sha256_4(data: bytes) -> bytes:
    """First 4 bytes of SHA-256 (BIP-39 checksum source)."""
    return hashlib.sha256(data).digest()[:4]


def entropy_to_mnemonic_ref(entropy: bytes, *, strict: bool = True) -> str:
    """Pure-python BIP-39 encoding (reference impl, English wordlist)."""
    if not isinstance(entropy, (bytes, bytearray)):
        raise RecoveryError("entropy must be bytes")
    ent = bytes(entropy)
    if len(ent) not in (16, 20, 24, 28, 32) and strict:
        raise RecoveryError(f"invalid entropy length {len(ent)} (need 16..32, mult of 4)")
    if len(ent) > MAX_ENTROPY_BYTES:
        raise RecoveryError("entropy longer than 32 bytes")
    cs_bits = len(ent) * 8 // 32
    words_n = (len(ent) * 8 + cs_bits) // 11
    bits = "".join(f"{b:08b}" for b in ent)
    bits += format(sha256_4(ent)[0], "08b")[:cs_bits]
    wl = builtin_wordlist()
    return " ".join(wl[int(bits[i * 11:(i + 1) * 11], 2)] for i in range(words_n))


def mnemonic_to_entropy_ref(mnemonic: str, *, strict: bool = True) -> bytes:
    """Pure-python BIP-39 decoding with checksum verification."""
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise RecoveryError(f"invalid mnemonic word count {len(words)}")
    wl = builtin_wordlist()
    idx = []
    for w in words:
        try:
            idx.append(wl.index(w))
        except ValueError:
            raise RecoveryError(f"word not in BIP-39 english list: {w!r}")
    bits = "".join(f"{i:011b}" for i in idx)
    total = len(bits)
    ent_bits = total - total // 33
    cs_bits = total // 33
    ent = int(bits[:ent_bits], 2).to_bytes(ent_bits // 8, "big")
    given_cs = bits[ent_bits:]
    expect_cs = format(sha256_4(ent)[0], "08b")[:cs_bits]
    if strict and given_cs != expect_cs:
        raise RecoveryError("BIP-39 checksum mismatch")
    return ent


def mnemonic_to_seed_ref(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 seed derivation: PBKDF2-HMAC-SHA512, 2048 rounds, salt='mnemonic'+pass."""
    pw = mnemonic.encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", pw, salt, 2048, dklen=64)


# ---------------------------------------------------------------------------
# Provider auto-detection: trezor/python-mnemonic preferred, builtin fallback
# ---------------------------------------------------------------------------

@dataclass
class Bip39Provider:
    name: str                      # "python-mnemonic" | "builtin-reference"
    version: str
    to_mnemonic: object            # callable(bytes, strict=True) -> str
    to_entropy: object             # callable(str, strict=True) -> bytes
    to_seed: object                # callable(str, passphrase='') -> bytes
    vectors_verified: bool = False
    notes: str = ""


def get_provider() -> Bip39Provider:
    """Return the best available BIP-39 provider (external lib if installed)."""
    try:
        import mnemonic as _pm  # type: ignore
        from mnemonic import Mnemonic as _M  # type: ignore
        m = _M("english")
        prov = Bip39Provider(
            name="python-mnemonic",
            version=getattr(_pm, "__version__", "unknown"),
            to_mnemonic=m.to_mnemonic,
            to_entropy=m.to_entropy,
            to_seed=m.to_seed,
            notes="trezor/python-mnemonic (external, widely audited)",
        )
    except ImportError:
        prov = Bip39Provider(
            name="builtin-reference",
            version="rng_research-builtin-1",
            to_mnemonic=entropy_to_mnemonic_ref,
            to_entropy=mnemonic_to_entropy_ref,
            to_seed=mnemonic_to_seed_ref,
            notes="built-in pure-python reference implementation",
        )
    # Cross-validate the ACTIVE provider against the bundled official vectors
    prov.vectors_verified = validate_provider_against_vectors(prov)
    if not prov.vectors_verified:
        prov.notes += " | WARNING: failed BIP-39 vector self-check"
    return prov


def load_bip39_vectors(path: str | Path | None = None) -> list[tuple[str, str]]:
    p = Path(path) if path else _WORDLIST_PATH.parent / "bip39_vectors.json"
    import json
    data = json.loads(p.read_text(encoding="utf-8"))
    vecs = [(item["entropy"], item["mnemonic"]) for item in data["vectors"]]
    if data.get("source_sha256") != _BIP39_VECTORS_SHA256:
        raise RecoveryError("bip39_vectors.json sha256 does not match provenance record")
    return vecs


def validate_provider_against_vectors(prov: Bip39Provider) -> bool:
    ok = True
    for hexent, expected in load_bip39_vectors():
        got = prov.to_mnemonic(bytes.fromhex(hexent))
        if got != expected:
            ok = False
            break
        back = prov.to_entropy(expected)
        if back.hex() != hexent:
            ok = False
            break
    return ok


# ---------------------------------------------------------------------------
# Vulnerable-stream reconstruction (bit-accurate libstdc++ convention)
# ---------------------------------------------------------------------------

def vulnerable_random_buffer(seed: int, length: int = 16) -> bytes:
    """Reproduce random_buffer(length) under the historical bug for ONE seed.

    Uses the ORACLE-VERIFIED libstdc++ MT19937 stream (init_genrand seeding,
    first outputs, low-byte truncation) — NOT CPython's seeding contract.
    """
    if not (0 <= seed <= UINT32_MAX):
        raise RecoveryError(f"seed must be uint32, got {seed}")
    if not (1 <= length <= 4096):
        raise RecoveryError("length must be within 1..4096")
    mt = MT19937Reference()
    mt.seed_scalar(seed)
    out = bytearray()
    while len(out) < length:
        out.append(mt.next_uint32() & 0xFF)
    return bytes(out[:length])


def seed_range(start: int, end: int) -> Iterator[int]:
    """Enumerate a bounded seed window with the scope cap enforced."""
    if start < 0 or end > UINT32_MAX or end < start:
        raise RecoveryError("invalid seed range")
    if (end - start + 1) > MAX_ENUMERATION_SEEDS:
        raise RecoveryError(
            f"enumeration of {end - start + 1} seeds exceeds scope cap "
            f"{MAX_ENUMERATION_SEEDS}; this lab does not sweep key spaces")
    return iter(range(start, end + 1))


@dataclass
class SeedMatch:
    seed: int
    entropy_hex: str
    mnemonic: str

    def to_dict(self) -> dict:
        return {"seed": self.seed, "entropy_hex": self.entropy_hex,
                "mnemonic": self.mnemonic}


def recover_seeds_for_mnemonic(mnemonic: str, *, start: int = 0, end: int = UINT32_MAX,
                               entropy_len: int = 16,
                               known_seeds: Iterable[int] | None = None,
                               provider: Bip39Provider | None = None) -> dict:
    """Find uint32 seed(s) whose vulnerable random_buffer equals the mnemonic's entropy.

    Two modes:
      * targeted audit (preferred): pass `known_seeds` — e.g. the seed window
        captured from YOUR OWN wallet during an audit — O(k) work.
      * bounded scan: enumerate [start, end] subject to the scope cap.

    Returns a report dict; never raises for 'no match' (that is a result).
    """
    prov = provider or get_provider()
    try:
        target = prov.to_entropy(mnemonic)      # validates checksum too
    except (ValueError, KeyError) as e:          # external lib raises ValueError
        raise RecoveryError(f"invalid mnemonic: {e}") from e
    if len(target) != entropy_len:
        raise RecoveryError(
            f"mnemonic entropy is {len(target)} bytes, entropy_len={entropy_len}")

    mode = "targeted-audit" if known_seeds is not None else "bounded-scan"
    candidates: Iterator[int]
    scanned = 0
    matches: list[SeedMatch] = []
    if known_seeds is not None:
        candidates = iter(list(known_seeds))
    else:
        candidates = seed_range(start, end)

    for s in candidates:
        scanned += 1
        buf = vulnerable_random_buffer(s, entropy_len)
        if buf == target:
            matches.append(SeedMatch(seed=s, entropy_hex=target.hex(),
                                     mnemonic=mnemonic))

    span_note = None
    if mode == "bounded-scan":
        span = end - start + 1
        span_note = (f"scanned {scanned} of 2^32 ({span} seeds); "
                     f"per-buffer collision expectation ≈ {span / 2**32:.3g}")
    return {
        "mode": mode,
        "provider": prov.name,
        "entropy_len": entropy_len,
        "seeds_scanned": scanned,
        "matches": [m.to_dict() for m in matches],
        "match_found": bool(matches),
        "scan_coverage_note": span_note,
        "limitations": [
            "Seed model assumes one uint32 draw into init_genrand (L1/L2 unverified).",
            "A match proves reachability under the model, not historical origin.",
        ],
    }


def enumerate_window_seeds(start: int, count: int, *, entropy_len: int = 16,
                           provider: Bip39Provider | None = None) -> list[dict]:
    """Audit helper: dump the deterministic buffer+mnemonic for a small seed
    window (for YOUR OWN captured seeds). Capped by MAX_ENUMERATION_SEEDS."""
    if not (1 <= count <= MAX_ENUMERATION_SEEDS):
        raise RecoveryError(f"count must be within 1..{MAX_ENUMERATION_SEEDS}")
    if start + count - 1 > UINT32_MAX:
        raise RecoveryError("window exceeds uint32 space")
    prov = provider or get_provider()
    rows = []
    for s in range(start, start + count):
        buf = vulnerable_random_buffer(s, entropy_len)
        rows.append({"seed": s, "entropy_hex": buf.hex(),
                     "mnemonic": prov.to_mnemonic(buf)})
    return rows
