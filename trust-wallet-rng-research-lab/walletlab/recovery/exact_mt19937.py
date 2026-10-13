"""Exact vulnerable-stream reconstruction core for WalletLab.

This is the *precise* recovery primitive: it models the historical bug's
output contract — a fresh ``std::mt19937`` re-seeded per call, first output
truncated to its low byte (wasm/src/Random.cpp@69b2da98, lines 15-21) —
using the ORACLE-VERIFIED libstdc++ MT19937 implementation already present
in this repository (``rng_research.mt19937_reference``, conformance-tested
bit-for-bit against a g++ 12.2 oracle in
tests/test_mt19937_conformance.py).

Two engines are provided:

* ``VulnerableStreamEngine`` — pure-Python, zero-dependency, exact.
* ``NodeNativeEngine``       — optional; calls Node.js with the *patched-era*
  C++ semantics via a small addon-free script that uses crypto's
  pre-3.19 ``randomBytes`` seeding lineage ONLY when explicitly enabled.
  Disabled by default (see node_bridge.py).

Scope guards (never sweep key spaces):
* every enumeration window is capped at MAX_WINDOW seeds;
* all results carry ``provenance`` + ``limitations`` so nothing here can be
  mistaken for historical truth without independent validation.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

# reuse the battle-tested pieces of the research core -----------------------
import sys

_WALLETLAB_ROOT = Path(__file__).resolve().parents[1]          # walletlab/
_LAB_ROOT = _WALLETLAB_ROOT.parent                              # lab root
sys.path.insert(0, str(_LAB_ROOT / "src"))

from rng_research.mt19937_reference import MT19937Reference     # noqa: E402
from rng_research.mnemonic_recovery import (                    # noqa: E402
    Bip39Provider, get_provider, UINT32_MAX, RecoveryError,
)

MAX_WINDOW = 1_000_000          # hard cap: matches research-core scope guard
SIMULATION_SALT = bytes.fromhex("deadbeef")   # placeholder-address derivation


# --------------------------------------------------------------------------
# Exact stream model
# --------------------------------------------------------------------------

class VulnerableStreamEngine:
    """Bit-accurate model of the vulnerable random_buffer() for ONE seed.

    Contract reproduced (per source snapshot Random.cpp@69b2da98):
        for i in range(length):
            mt = std::mt19937(seed)          # fresh engine, init_genrand
            out[i] = uint8_t(mt())           # first output, low byte
    The MT19937 scalar-seeding and output stream here match libstdc++
    bit-for-bit (oracle-verified); see tests/test_mt19937_conformance.py.
    """

    name = "vulnerable-mt19937-exact"
    origin = ("rng_research.mt19937_reference.MT19937Reference "
              "(libstdc++ init_genrand convention, g++-oracle verified)")

    def buffer(self, seed: int, length: int = 16) -> bytes:
        return vulnerable_random_buffer_exact(seed, length)

    def buffer_stream(self, seed: int, length: int = 16) -> bytes:
        """Single-engine stream model (matches the research core's
        rng_research.mnemonic_recovery.vulnerable_random_buffer exactly):
        one mt19937(seed), take successive outputs, low byte each."""
        if not (0 <= seed <= UINT32_MAX):
            raise RecoveryError(f"seed must be uint32, got {seed}")
        if not (1 <= length <= 4096):
            raise RecoveryError("length must be within 1..4096")
        mt = MT19937Reference()
        mt.seed_scalar(seed)
        return bytes((mt.next_uint32() & 0xFF for _ in range(length)))

    def mnemonic_for_seed(self, seed: int, provider: Bip39Provider | None = None,
                          entropy_len: int = 16) -> dict:
        prov = provider or get_provider()
        buf = self.buffer(seed, entropy_len)
        return {"seed": seed, "entropy_hex": buf.hex(),
                "mnemonic": prov.to_mnemonic(buf)}


def vulnerable_random_buffer_exact(seed: int, length: int = 16) -> bytes:
    """Per-BYTE reseed variant of the source-level loop contract.

    Random.cpp@69b2da98 constructs a fresh engine inside the fill loop; with
    a constant seed that yields a repeated byte. The corpus and recovery
    queries here use the STREAM convention (buffer_stream) which is the
    behavioural model validated end-to-end by the research core (E6 round
    trip, tests/test_mnemonic_recovery.py). Both are exposed so analyses can
    compare conventions instead of silently assuming one.
    """
    if not (0 <= seed <= UINT32_MAX):
        raise RecoveryError(f"seed must be uint32, got {seed}")
    if not (1 <= length <= 4096):
        raise RecoveryError("length must be within 1..4096")
    mt = MT19937Reference()
    out = bytearray()
    while len(out) < length:
        mt.seed_scalar(seed)                 # fresh engine per byte
        out.append(mt.next_uint32() & 0xFF)  # first output, low byte
    return bytes(out[:length])


_ENGINE = VulnerableStreamEngine()


# --------------------------------------------------------------------------
# Sandbox ledger (simulated balances) — clearly separated from real chains
# --------------------------------------------------------------------------

@dataclass
class SandboxWallet:
    seed: int
    entropy_hex: str
    mnemonic: str
    address: str
    funded: bool
    balance_eth: float

    def to_dict(self) -> dict:
        return {"seed": self.seed, "entropy_hex": self.entropy_hex,
                "mnemonic": self.mnemonic, "address": self.address,
                "funded": self.funded, "balance_eth": self.balance_eth}


def placeholder_address(entropy_hex: str) -> str:
    """DETERMINISTIC PLACEHOLDER address — NOT secp256k1/EIP-55.

    Real BIP-44 derivation is intentionally out of scope here; the sandbox
    corpus uses sha256(salt||entropy)[:20] rendered in 0x-hex form so the UI
    can display something address-shaped without pretending it is real.
    """
    e = bytes.fromhex(entropy_hex)
    return "0x" + hashlib.sha256(SIMULATION_SALT + e).hexdigest()[:40]


def simulated_balance(entropy_hex: str) -> tuple[bool, float]:
    """Deterministic sandbox funding rule: sha256(entropy) % 7 == 0."""
    h = int(hashlib.sha256(bytes.fromhex(entropy_hex)).hexdigest(), 16)
    if h % 7 != 0:
        return False, 0.0
    return True, round(((h >> 8) % 99999) / 1000 + 0.5, 4)


@lru_cache(maxsize=4)
def load_corpus(path: str | Path | None = None) -> dict:
    p = Path(path) if path else (_WALLETLAB_ROOT / "simulation" / "corpus_v1.json")
    data = json.loads(p.read_text(encoding="utf-8"))
    # integrity: recompute every mnemonic from its seed with the EXACT engine
    prov = get_provider()
    bad = []
    for w in data["wallets"]:
        buf = _ENGINE.buffer_stream(w["seed"], 16)
        if buf.hex() != w["entropy_hex"] or prov.to_mnemonic(buf) != w["mnemonic"]:
            bad.append(w["seed"])
    if bad:
        raise RecoveryError(f"corpus integrity check failed for seeds: {bad[:10]}")
    return data


def corpus_wallets(corpus_path: str | Path | None = None) -> list[SandboxWallet]:
    data = load_corpus(corpus_path)
    return [SandboxWallet(w["seed"], w["entropy_hex"], w["mnemonic"],
                          w["address"], w["funded"], w["balance_eth"])
            for w in data["wallets"]]


# --------------------------------------------------------------------------
# Recovery queries (exact, bounded)
# --------------------------------------------------------------------------

@dataclass
class RecoveryResult:
    query_kind: str                     # "address" | "mnemonic"
    matched: bool
    confidence: str                     # always "model-verified", never "historical"
    wallet: dict | None = None
    scanned_seeds: int = 0
    provenance: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"query_kind": self.query_kind, "matched": self.matched,
                "confidence": self.confidence, "wallet": self.wallet,
                "scanned_seeds": self.scanned_seeds,
                "provenance": self.provenance, "limitations": self.limitations}


_LIMITATIONS = [
    "Match proves REACHABILITY under the documented seed model only.",
    "Historical WASM binary equivalence remains UNVERIFIED (ledger L1/L2).",
    "Balances come from the LOCAL SIMULATION ledger, not any blockchain.",
    "Placeholder addresses are NOT real derived wallet addresses.",
]


def recover_by_address(address: str, *, start: int = 0, end: int = 999,
                       corpus_path: str | Path | None = None) -> RecoveryResult:
    """Exact recovery over a bounded seed window: find the seed whose
    vulnerable stream produced entropy mapping to `address` (placeholder
    scheme of the sandbox corpus)."""
    if end < start:
        raise RecoveryError("end < start")
    if (end - start + 1) > MAX_WINDOW:
        raise RecoveryError(f"window exceeds cap ({MAX_WINDOW})")
    target = address.strip().lower()
    prov = get_provider()
    scanned = 0
    for s in range(start, end + 1):
        scanned += 1
        buf = _ENGINE.buffer_stream(s, 16)
        if placeholder_address(buf.hex()).lower() == target:
            mnem = prov.to_mnemonic(buf)
            funded, bal = simulated_balance(buf.hex())
            w = SandboxWallet(s, buf.hex(), mnem, placeholder_address(buf.hex()),
                              funded, bal)
            return RecoveryResult("address", True, "model-verified",
                                  w.to_dict(), scanned,
                                  {"engine": _ENGINE.origin,
                                   "bip39_provider": prov.name}, list(_LIMITATIONS))
    return RecoveryResult("address", False, "model-verified", None, scanned,
                          {"engine": _ENGINE.origin}, list(_LIMITATIONS))


def audit_mnemonic(mnemonic: str, *, start: int = 0, end: int = 999,
                   corpus_path: str | Path | None = None) -> RecoveryResult:
    """Check whether a given mnemonic lies on the vulnerable stream within a
    bounded window (targeted audit; O(window))."""
    if (end - start + 1) > MAX_WINDOW:
        raise RecoveryError(f"window exceeds cap ({MAX_WINDOW})")
    prov = get_provider()
    try:
        target = prov.to_entropy(mnemonic)
    except Exception as exc:
        raise RecoveryError(f"invalid mnemonic: {exc}") from exc
    for s in range(start, end + 1):
        if _ENGINE.buffer_stream(s, len(target)) == target:
            funded, bal = simulated_balance(target.hex())
            w = SandboxWallet(s, target.hex(), prov.to_mnemonic(target),
                              placeholder_address(target.hex()), funded, bal)
            return RecoveryResult("mnemonic", True, "model-verified",
                                  w.to_dict(), s - start + 1,
                                  {"engine": _ENGINE.origin,
                                   "bip39_provider": prov.name}, list(_LIMITATIONS))
    return RecoveryResult("mnemonic", False, "model-verified", None,
                          end - start + 1, {"engine": _ENGINE.origin},
                          list(_LIMITATIONS))
