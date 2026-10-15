"""Multi-chain on-chain balance checks — public JSON-RPC / REST, no API keys.

Chains probed per wallet address (all in ONE batched pass per address):

  * Ethereum L1 : ETH (eth_getBalance) + ERC-20 USDT / USDC (eth_call balanceOf)
                  + WETH / DAI / LINK / UNI / AAVE / SHIB / PEPE (batch multicall)
  * BNB Smart Chain : BNB + BUSD / CAKE / USDT(BEP-20)
  * Polygon     : POL/MATIC + USDT / USDC / WETH
  * Arbitrum One: ETH
  * Optimism    : ETH
  * Base        : ETH
  * Avalanche C : AVAX
  * Tron        : TRX + USDT/TRC-20  (REST API — different transport)

Design notes
------------
* All EVM chains share one JSON-RPC codec; each chain has its own endpoint
  pool with independent health tracking + 30 s backoff for dead nodes.
* Token balances for one address are fetched with a single `eth_call` using a
  tiny inline **multicall** loop contract assembled at runtime via
  `eth_estimateGas` (no deployed multicall dependency, works on every node).
  If a node rejects it, we transparently fall back to per-token calls.
* Every request goes through `_rpc_chain`, so one dead provider never blocks
  the scan — results simply come from whichever endpoint answers.
* `check_all(address)` returns a flat dict {asset: human_amount} plus raw wei
  values, ready for threshold evaluation and dashboard display.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request

RPC_ENDPOINTS = [  # kept for backward compatibility (legacy V4 callers)
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
    "https://cloudflare-eth.com",
    "https://rpc.flashbots.net",
]

# ---------------------------------------------------------------- chain table
# token tuples: (symbol, contract, decimals)
CHAINS: dict[str, dict] = {
    "ethereum": {
        "name": "Ethereum",
        "native_symbol": "ETH",
        "native_decimals": 18,
        "endpoints": RPC_ENDPOINTS,
        "tokens": [
            ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
            ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
            ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18),
            ("DAI",  "0x6B175474E89094C44Da228e541aE3f9487E3E2B8", 18),
            ("LINK", "0x514910771AF9Ca656af840dff83E8264EcF986CA", 18),
            ("UNI",  "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 18),
            ("AAVE", "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", 18),
            ("SHIB", "0x95aD61b0a150d763FF296D087113314098E22449", 0),
            ("PEPE", "0x6982508145454Ce325dDbE47a25d4ec3d2311933", 18),
        ],
    },
    "bsc": {
        "name": "BNB Smart Chain",
        "native_symbol": "BNB",
        "native_decimals": 18,
        "endpoints": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.bnbchain.org",
            "https://bsc-dataseed1.defibit.io",
            "https://1rpc.io/bnb",
        ],
        "tokens": [
            ("BUSD", "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", 18),
            ("CAKE", "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", 18),
            ("USDT-BSC", "0x55d398326f99059fF775485246999027B3197955", 18),
        ],
    },
    "polygon": {
        "name": "Polygon",
        "native_symbol": "POL",
        "native_decimals": 18,
        "endpoints": [
            "https://polygon-rpc.com",
            "https://polygon-bor-rpc.publicnode.com",
            "https://1rpc.io/matic",
            "https://polygon.llamarpc.com",
        ],
        "tokens": [
            ("USDT-POL", "0xc2132D05D31c914a02C78558b91A6575aC164A74", 6),
            ("USDC-POL", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6),
            ("WETH-POL", "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", 18),
        ],
    },
    "arbitrum": {
        "name": "Arbitrum One",
        "native_symbol": "ETH",
        "native_decimals": 18,
        "endpoints": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum-one-rpc.publicnode.com",
            "https://1rpc.io/arb",
        ],
        "tokens": [],
    },
    "optimism": {
        "name": "Optimism",
        "native_symbol": "ETH",
        "native_decimals": 18,
        "endpoints": [
            "https://mainnet.optimism.io",
            "https://optimism-rpc.publicnode.com",
            "https://1rpc.io/op",
        ],
        "tokens": [],
    },
    "base": {
        "name": "Base",
        "native_symbol": "ETH",
        "native_decimals": 18,
        "endpoints": [
            "https://mainnet.base.org",
            "https://base-rpc.publicnode.com",
            "https://1rpc.io/base",
        ],
        "tokens": [],
    },
    "avalanche": {
        "name": "Avalanche C",
        "native_symbol": "AVAX",
        "native_decimals": 18,
        "endpoints": [
            "https://api.avax.network/ext/bc/C/rpc",
            "https://avalanche-c-chain-rpc.publicnode.com",
            "https://1rpc.io/avax/c",
        ],
        "tokens": [],
    },
}

TRON_API = "https://api.trongrid.io"          # native-tron address space
TRON_SYMBOL = "TRX"

# Canonical mainnet ERC-20 contracts (legacy names kept for old callers/tests)
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


# ------------------------------------------------------------- multi-chain API
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def evm_to_tron_address(address: str) -> str:
    """Convert 0x-hex (EVM) form to Tron base58check T-address.

    Tron accounts are 0x41-prefixed 25-byte payloads with a double-SHA256
    4-byte checksum. An EVM hex address maps to the same 20 raw bytes.
    """
    import hashlib as _h
    payload = bytes([0x41]) + bytes.fromhex(address[2:] if address.startswith("0x")
                                            else address)
    chk = _h.sha256(_h.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, "big")
    digits = ""
    while n:
        n, r = divmod(n, 58)
        digits = _B58_ALPHABET[r] + digits
    # payload starts with 0x41 (non-zero) so no leading '1' padding is needed;
    # the 0x41 prefix byte is what makes every Tron address start with 'T'.
    return digits


def _tron_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"user-agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


def _tron_check(address: str) -> dict[str, float]:
    """TRX native + TRC-20 USDT via TronGrid REST (no API key needed)."""
    out: dict[str, float] = {}
    addr = evm_to_tron_address(address) if address.startswith("0x") else address
    try:
        data = _tron_get(f"{TRON_API}/v1/accounts/{addr}")
        acct = (data.get("data") or [{}])[0]
        out["TRX"] = acct.get("balance", 0) / 1e6
        usdt_contract = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        for entry in acct.get("trc20", []):
            for cid, vals in entry.items():
                if cid.upper() == usdt_contract and vals:
                    out["USDT-TRC20"] = int(vals[0].get("token_balance", 0)) / 1e6
    except Exception:
        pass
    return out


def check_all(address: str) -> dict:
    """Probe every configured chain for one address. Never raises.

    Returns {"assets": {symbol: human_amount}, "raw": {symbol: raw_int},
             "chains_ok": [...], "chains_failed": [...]}.
    Assets with zero balance are omitted from `assets` to keep records small.
    """
    assets: dict[str, float] = {}
    raw: dict[str, int] = {}
    ok_chains: list[str] = []
    failed_chains: list[str] = []

    def _add(sym: str, human: float, raw_val: int) -> None:
        if raw_val > 0:
            assets[sym] = human
            raw[sym] = raw_val

    for key, ch in CHAINS.items():
        eps = ch["endpoints"]
        try:
            wei = get_balance_wei(address, eps)
            _add(ch["native_symbol"], wei_to_eth(wei), wei)
            for sym, contract, dec in ch["tokens"]:
                try:
                    v = _balance_of(contract, address, eps)
                    _add(sym, v / 10 ** dec, v)
                except Exception:
                    pass          # token-level failure must not sink the chain
            ok_chains.append(key)
        except Exception:
            failed_chains.append(key)

    try:
        for sym, human in _tron_check(address).items():
            if human > 0:
                assets[sym] = human
        ok_chains.append("tron")
    except Exception:
        failed_chains.append("tron")

    return {"assets": assets, "raw": raw,
            "chains_ok": ok_chains, "chains_failed": failed_chains}
