"""On-chain balance checks via public Ethereum JSON-RPC.

- ETH: eth_getBalance
- USDT / USDC (ERC-20): eth_call balanceOf on the canonical mainnet contracts

No API key required. Five public endpoints with automatic failover and a
30-second backoff window for dead nodes (they are retried once the cooldown
expires). Standard browser User-Agent avoids 403 blocks on eth_call.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request

RPC_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
    "https://cloudflare-eth.com",
    "https://rpc.flashbots.net",
]

# Canonical mainnet ERC-20 contracts
USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"   # 6 decimals
USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"   # 6 decimals

BALANCEOF_SELECTOR = "0x70a08231"

TIMEOUT = 8.0
BACKOFF_SEC = 30.0          # dead-node cooldown
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_lock = threading.Lock()
_failed_until: dict[str, float] = {}   # endpoint -> monotonic time it may be retried


def _healthy_endpoints() -> list[str]:
    now = time.monotonic()
    with _lock:
        ok = [u for u in RPC_ENDPOINTS if _failed_until.get(u, 0.0) <= now]
        # all dead? fall back to whichever recovers soonest
        if not ok:
            ok = sorted(RPC_ENDPOINTS, key=lambda u: _failed_until.get(u, 0.0))[:1]
        return ok


def _mark_failed(url: str) -> None:
    with _lock:
        _failed_until[url] = time.monotonic() + BACKOFF_SEC


def _mark_ok(url: str) -> None:
    with _lock:
        _failed_until.pop(url, None)


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "user-agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


def _rpc(method: str, params: list, endpoints: list[str] | None = None) -> str:
    """Run one JSON-RPC call with failover + backoff. Returns hex result."""
    last_err: Exception | None = None
    for url in (endpoints or _healthy_endpoints()):
        try:
            out = _post(url, {"jsonrpc": "2.0", "method": method,
                              "params": params, "id": 1})
            if "result" in out:
                _mark_ok(url)
                return out["result"]
            last_err = RuntimeError(f"{url}: {out.get('error')}")
            _mark_failed(url)
        except Exception as exc:  # noqa: BLE001 - failover by design
            last_err = exc
            _mark_failed(url)
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def _balance_of(contract: str, address: str,
                endpoints: list[str] | None = None) -> int:
    data = BALANCEOF_SELECTOR + address[2:].lower().rjust(64, "0")
    res = _rpc("eth_call", [{"to": contract, "data": data}, "latest"], endpoints)
    return int(res, 16) if res and res != "0x" else 0


def get_balance_wei(address: str, endpoints: list[str] | None = None) -> int:
    """Return ETH balance in wei. Raises RuntimeError if every endpoint fails."""
    res = _rpc("eth_getBalance", [address, "latest"], endpoints)
    return int(res, 16)


def get_token_balances(address: str,
                       endpoints: list[str] | None = None) -> tuple[int, int]:
    """Return (usdt_raw, usdc_raw) integer balances (6 decimals each)."""
    return (_balance_of(USDT_CONTRACT, address, endpoints),
            _balance_of(USDC_CONTRACT, address, endpoints))


def wei_to_eth(wei: int) -> float:
    return wei / 1e18


def raw_to_usd(raw: int) -> float:
    """USDT/USDC use 6 decimals."""
    return raw / 1e6
