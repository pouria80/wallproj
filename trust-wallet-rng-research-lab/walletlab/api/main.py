"""WalletLab API — local-only FastAPI service for the wallet dashboard.

Endpoints (all JSON, served under /api):
  GET  /api/health                 readiness + engine provenance
  GET  /api/stats                  totals: wallets, funded/empty, balance sum
  GET  /api/wallets                list with filters: funded, q, offset, limit
  GET  /api/wallets/{seed}         one wallet by seed
  POST /api/recover/address        {address,start,end} -> exact recovery result
  POST /api/recover/mnemonic       {mnemonic,start,end} -> audit result
  GET  /api/engine                 model/provenance/limitations metadata

Safety: binds 127.0.0.1 only; no network egress; enumeration capped at
MAX_WINDOW seeds; every response carries honest labels. Static build of the
React dashboard is mounted at / when present (web/dist).
"""
from __future__ import annotations

import sys
from pathlib import Path

WALLETLAB_ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = WALLETLAB_ROOT.parent
sys.path.insert(0, str(LAB_ROOT / "src"))
sys.path.insert(0, str(WALLETLAB_ROOT))

from fastapi import FastAPI, HTTPException, Query            # noqa: E402
from fastapi.middleware.cors import CORSMiddleware           # noqa: E402
from pydantic import BaseModel, Field                        # noqa: E402

from recovery.exact_mt19937 import (                          # noqa: E402
    MAX_WINDOW, RecoveryError, _ENGINE, audit_mnemonic,
    corpus_wallets, load_corpus, recover_by_address,
)


class AddressQuery(BaseModel):
    address: str = Field(min_length=3, max_length=80)
    start: int = 0
    end: int = 999


class MnemonicQuery(BaseModel):
    mnemonic: str = Field(min_length=12)
    start: int = 0
    end: int = 999


def create_app() -> FastAPI:
    app = FastAPI(title="WalletLab", version="1.0.0",
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(CORSMiddleware,
                       allow_origins=["http://localhost:5174",
                                      "http://127.0.0.1:5174"],
                       allow_methods=["*"], allow_headers=["*"])

    @app.get("/api/health")
    def health():
        data = load_corpus()
        return {"status": "ok", "corpus": data["corpus"],
                "wallets_loaded": len(data["wallets"]),
                "engine": _ENGINE.name,
                "enumeration_cap": MAX_WINDOW,
                "network_egress": False}

    @app.get("/api/stats")
    def stats():
        ws = corpus_wallets()
        funded = [w for w in ws if w.funded]
        return {
            "total_wallets": len(ws),
            "funded": len(funded),
            "empty": len(ws) - len(funded),
            "total_balance_eth": round(sum(w.balance_eth for w in funded), 4),
            "max_balance_eth": max((w.balance_eth for w in funded), default=0.0),
            "seed_window": [min(w.seed for w in ws), max(w.seed for w in ws)],
            "network": "SIMULATION-LOCAL",
            "disclaimer": ("Synthetic sandbox corpus. Balances are simulated "
                           "locally; addresses are SHA-256 placeholders."),
        }

    @app.get("/api/wallets")
    def wallets(funded: bool | None = None, q: str = "",
               offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)):
        rows = [w.to_dict() for w in corpus_wallets()]
        if funded is not None:
            rows = [r for r in rows if r["funded"] == funded]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in r["address"] or ql in r["mnemonic"]
                    or ql == str(r["seed"])]
        return {"total": len(rows), "offset": offset, "limit": limit,
                "items": rows[offset:offset + limit]}

    @app.get("/api/wallets/{seed}")
    def wallet_one(seed: int):
        for w in corpus_wallets():
            if w.seed == seed:
                return w.to_dict()
        raise HTTPException(404, f"no corpus wallet for seed {seed}")

    @app.post("/api/recover/address")
    def recover_addr(body: AddressQuery):
        try:
            return recover_by_address(body.address, start=body.start,
                                      end=body.end).to_dict()
        except RecoveryError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/recover/mnemonic")
    def recover_mnem(body: MnemonicQuery):
        try:
            return audit_mnemonic(body.mnemonic, start=body.start,
                                  end=body.end).to_dict()
        except RecoveryError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/engine")
    def engine_info():
        from rng_research.mnemonic_recovery import get_provider
        prov = get_provider()
        return {
            "stream_engine": _ENGINE.name,
            "origin": _ENGINE.origin,
            "conformance": ("bit-for-bit vs g++ 12.2 std::mt19937 oracle — "
                            "tests/test_mt19937_conformance.py"),
            "bip39_provider": prov.name,
            "bip39_vectors_verified": prov.vectors_verified,
            "chain": ("uint32 seed -> libstdc++ MT19937 stream -> low-byte "
                      "truncation (Random.cpp@69b2da98) -> BIP-39 entropy -> "
                      "mnemonic"),
            "limitations": [
                "Historical WASM binary equivalence UNVERIFIED (ledger L1/L2).",
                "Balances and addresses come from the LOCAL simulation ledger.",
                "A match proves reachability under the model, not origin.",
            ],
        }

    # static SPA (built dashboard) ------------------------------------------
    dist = WALLETLAB_ROOT / "web" / "dist"
    if dist.exists():
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse

        @app.get("/")
        def index():
            return FileResponse(dist / "index.html")

        app.mount("/", StaticFiles(directory=dist, html=True), name="spa")

    return app


app = create_app()
