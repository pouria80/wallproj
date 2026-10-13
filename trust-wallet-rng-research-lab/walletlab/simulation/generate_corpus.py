"""Regenerate the WalletLab sandbox corpus deterministically.

Usage:  python simulation/generate_corpus.py [n_wallets]

Every wallet is recomputed from its seed with the EXACT recovery engine, so
`corpus_v1.json` can always be reproduced and integrity-checked
(walletlab/tests/test_walletlab.py asserts byte-identical regeneration).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # walletlab/
sys.path.insert(0, str(ROOT.parent / "src"))
sys.path.insert(0, str(ROOT))

from recovery.exact_mt19937 import (                 # noqa: E402
    _ENGINE, placeholder_address, simulated_balance)
from rng_research.mnemonic_recovery import get_provider   # noqa: E402


def build(n: int = 1000) -> dict:
    prov = get_provider()
    rows = []
    for s in range(n):
        buf = _ENGINE.buffer_stream(s, 16)
        funded, bal = simulated_balance(buf.hex())
        rows.append({"seed": s, "entropy_hex": buf.hex(),
                     "mnemonic": prov.to_mnemonic(buf),
                     "address": placeholder_address(buf.hex()),
                     "funded": funded, "balance_eth": bal})
    return {
        "corpus": "trustwallet-cve-2023-31290-sandbox-v1",
        "warning": ("SYNTHETIC LOCAL SANDBOX ONLY — mnemonics were NOT produced "
                    "by the historical Trust Wallet build; addresses are "
                    "SHA-256 placeholders (not secp256k1/EIP-55); balances are "
                    "simulated from a deterministic rule over entropy hashes. "
                    "No network I/O, no real funds."),
        "network": "SIMULATION-LOCAL",
        "chain_id": 31337,
        "generation": {
            "model": ("vulnerable random_buffer(seed) — libstdc++ MT19937 "
                      "stream convention, low-byte truncation"),
            "seeds": f"uint32 [0,{n})", "entropy_len": 16},
        "stats": {"total": len(rows),
                  "funded": sum(r["funded"] for r in rows)},
        "wallets": rows,
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    out = ROOT / "simulation" / "corpus_v1.json"
    data = build(n)
    text = json.dumps(data, indent=1)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} sha256={hashlib.sha256(text.encode()).hexdigest()[:16]} "
          f"stats={data['stats']}")
