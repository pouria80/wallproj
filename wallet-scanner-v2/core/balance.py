"""On-chain balance check via public Ethereum JSON-RPC (eth_getBalance).

No API key required. Multiple public endpoints with automatic failover.
"""
from __future__ import annotations

import json
import urllib.request

RPC_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
]

TIMEOUT = 8.0


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"content-type": "application/json",
                 "user-agent": "Mozilla/5.0 (wallet-scanner-v2)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


def get_balance_wei(address: str, endpoints: list[str] | None = None) -> int:
    """Return ETH balance in wei. Raises RuntimeError if every endpoint fails."""
    last_err: Exception | None = None
    for url in (endpoints or RPC_ENDPOINTS):
        try:
            out = _post(url, {"jsonrpc": "2.0", "method": "eth_getBalance",
                              "params": [address, "latest"], "id": 1})
            if "result" in out:
                return int(out["result"], 16)
            last_err = RuntimeError(f"{url}: {out.get('error')}")
        except Exception as exc:  # noqa: BLE001 - failover by design
            last_err = exc
    raise RuntimeError(f"all RPC endpoints failed: {last_err}")


def wei_to_eth(wei: int) -> float:
    return wei / 1e18
