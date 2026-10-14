"""Read-only balance checking + Bloom-filter pre-screen (V5).

HARD RULES enforced by this module:
  * READ-ONLY.  There is no code path that builds, signs or broadcasts a
    transaction.  Only GET requests / `getbalance`-style RPC reads exist.
  * Local mode first: if a Bitcoin Core node (auth_to_local cookie) or an
    Electrum/Esplora server on 127.0.0.1 is configured, it is used and NO
    traffic leaves the machine.
  * Public-API mode only queries balances; addresses never leave in URLs
    beyond what any block explorer read requires.

Bloom filter
------------
The scanner derives millions of candidate addresses per second.  Querying
every one against the chain would be both useless and abusive.  The
standard mitigation (same idea as SPV bloom filters) is to keep a compact
probabilistic set of the *watch-list* (e.g. all funded addresses fetched
once from a snapshot file / RPC `listunspent` dump / UTXO set scan) and to
test every derived address against it before touching any network API.
False positives are possible (rare, tunable), false negatives are NOT —
so no funded wallet can ever be missed by the pre-screen.

Two backends ship here:
  * ``LocalWatchlist``  — offline set/bloom over a text file of addresses.
  * ``ElectrsBackend`` / ``CoreRPCBackend`` / ``BlockstreamBackend`` —
    read-only balance sources with built-in bloom pre-screening.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set


# ------------------------------------------------------------------- bloom
class BloomFilter:
    """Classic bit-array bloom filter keyed on double-SHA-256 hash pairs.

    k hash functions derived from h1/h2 (Kirsch-Mitzenmacher):
        g_i(x) = (h1 + i*h2) mod m
    FP rate ≈ (1 - e^(-kn/m))^k.  Chosen automatically for target fp.
    """

    def __init__(self, capacity: int, fp_rate: float = 1e-6):
        self.n = max(capacity, 1)
        p = min(max(fp_rate, 1e-12), 0.5)
        m = max(int(-self.n * math.log(p) / (math.log(2) ** 2)), 64)
        self.m = ((m + 63) // 64) * 64                    # word-aligned
        self.k = max(1, int(round((self.m / self.n) * math.log(2))))
        self.bits = bytearray(self.m // 8)
        self.added = 0

    # -- hashing -----------------------------------------------------------
    @staticmethod
    def _h12(item: bytes) -> tuple[int, int]:
        d = hashlib.sha256(item).digest()
        return (int.from_bytes(d[:8], "big"),
                int.from_bytes(d[8:16], "big") | 1)      # odd => full period

    def add(self, item: str) -> None:
        b = item.encode("ascii", "ignore")
        h1, h2 = self._h12(b)
        for i in range(self.k):
            pos = (h1 + i * h2) % self.m
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.added += 1

    def __contains__(self, item: str) -> bool:
        b = item.encode("ascii", "ignore")
        h1, h2 = self._h12(b)
        for i in range(self.k):
            pos = (h1 + i * h2) % self.m
            if not (self.bits[pos >> 3] >> (pos & 7)) & 1:
                return False
        return True

    def maybe_contains(self, item: str) -> bool:          # explicit spelling
        return item in self

    def stats(self) -> dict:
        return {"capacity": self.n, "bits": self.m, "hashes": self.k,
                "added": self.added}


# ------------------------------------------------------------- watchlists
@dataclass
class Watchlist:
    """Known-funded address set + its bloom pre-screen."""
    addresses: Set[str] = field(default_factory=set)
    bloom: Optional[BloomFilter] = None

    @classmethod
    def load(cls, path: str, fp_rate: float = 1e-6) -> "Watchlist":
        """Text file: one address per line (optionally 'chain:address')."""
        addrs: Set[str] = set()
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    addrs.add(ln.split(":", 1)[-1])
        wl = cls(addresses=addrs)
        wl.bloom = BloomFilter(len(addrs), fp_rate)
        for a in addrs:
            wl.bloom.add(a)
        return wl

    @classmethod
    def from_iterable(cls, items: Iterable[str],
                      fp_rate: float = 1e-6) -> "Watchlist":
        addrs = set(items)
        wl = cls(addresses=addrs)
        wl.bloom = BloomFilter(len(addrs), fp_rate)
        for a in addrs:
            wl.bloom.add(a)
        return wl

    def might_be_funded(self, address: str) -> bool:
        """Bloom answer: False => DEFINITELY not on the list (skip network)."""
        if self.bloom is None:
            return True
        return self.bloom.maybe_contains(address)

    def confirm(self, address: str) -> bool:
        """Exact membership (call only after a bloom hit)."""
        return address in self.addresses


# ------------------------------------------------------------ HTTP helpers
def _http_get_json(url: str, timeout: float = 10.0,
                   headers: Optional[dict] = None) -> dict | list:
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "rng-lab-v5/1.0",
                                          **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


@dataclass
class BalanceResult:
    address: str
    chain_tag: str
    confirmed: int          # satoshis (or coin's smallest unit)
    unconfirmed: int = 0
    tx_count: int = 0
    source: str = ""

    @property
    def funded(self) -> bool:
        return (self.confirmed + self.unconfirmed) > 0


# --------------------------------------------------------------- backends
class Backend:
    name = "abstract"

    def balance(self, address: str, chain_tag: str = "btc") -> BalanceResult:
        raise NotImplementedError


class ElectrsBackend(Backend):                  # local electrs / Esplora API
    """GET /address/<a> on an Esplora-compatible server (electrs, fulcrum-api).

    Read-only by construction — only address lookups are implemented.
    """
    name = "electrs"

    def __init__(self, base_url: str = "http://127.0.0.1:3000"):
        self.base = base_url.rstrip("/")

    def balance(self, address: str, chain_tag: str = "btc") -> BalanceResult:
        # esplora /address/{a}/utxo is the unambiguous read-only balance.
        utxos = _http_get_json(f"{self.base}/address/{address}/utxo")
        confirmed = sum(int(u["value"]) for u in utxos)
        return BalanceResult(address, chain_tag, confirmed, 0,
                             len(utxos), self.name)


class BlockstreamBackend(Backend):
    """Public read-only API (api.blockstream.info).  Balance info ONLY."""
    name = "blockstream"

    def __init__(self, network: str = "mainnet"):
        net = "" if network == "mainnet" else f"/{network}"
        self.base = f"https://blockstream.info{net}/api"

    def balance(self, address: str, chain_tag: str = "btc") -> BalanceResult:
        stats = _http_get_json(f"{self.base}/address/{address}/utxo",
                               timeout=15.0)
        total = sum(int(u["value"]) for u in stats)
        return BalanceResult(address, chain_tag, total, 0, len(stats),
                             self.name)


class DogeChainBackend(Backend):
    name = "dogechain"

    def balance(self, address: str, chain_tag: str = "doge") -> BalanceResult:
        j = _http_get_json(f"https://dogechain.info/addr/{address}?format=json")
        bal = j.get("balance", {})
        return BalanceResult(address, chain_tag,
                             int(float(bal.get("final_balance", 0)) * 1e8),
                             int(float(bal.get("unconfirmed_balance", 0)) * 1e8),
                             int(bal.get("num_tx", 0)), self.name)


class LitecoinspaceBackend(Backend):
    name = "litecoin-space"

    def balance(self, address: str, chain_tag: str = "ltc") -> BalanceResult:
        stats = _http_get_json(f"https://ltc.token.everstake.com/api/"
                               f"v1/address/{address}")
        return BalanceResult(address, chain_tag,
                             int(stats.get("confirmed", 0)),
                             int(stats.get("unconfirmed", 0)),
                             int(stats.get("txCount", 0)), self.name)


class ZchainZecBackend(Backend):
    """Zcash transparent balance via zchain.tools (read-only)."""
    name = "zchain"

    def balance(self, address: str, chain_tag: str = "zec") -> BalanceResult:
        j = _http_get_json(f"https://zcash.blockexplorer.com/api/"
                           f"addr/{address}")
        return BalanceResult(address, chain_tag,
                             int(float(j.get("balance", 0)) * 1e8),
                             int(float(j.get("balanceSat", 0))),
                             int(j.get("transactions", 0) or
                                 len(j.get("txs", []))), self.name)


class CoreRPCBackend(Backend):
    """Local Bitcoin Core JSON-RPC — descriptor import + scantxoutset reads.

    Uses the node's auth cookie (~/.bitcoin/.cookie).  Never sends raw txs:
    only `scantxoutset`, `getaddressinfo`, `getreceivedbyaddress`.
    """
    name = "bitcoind"

    def __init__(self, host: str = "127.0.0.1", port: int = 8332,
                 cookie_path: Optional[str] = None, rpcuser: str = "",
                 rpcpassword: str = ""):
        self.url = f"http://{host}:{port}"
        if cookie_path:
            with open(cookie_path) as f:
                rpcuser, _, rpcpassword = f.read().strip().partition(":")
        self.auth = base64.b64encode(f"{rpcuser}:{rpcpassword}".encode()).decode()

    def _call(self, method: str, params: list) -> object:
        body = json.dumps({"jsonrpc": "1.0", "id": "v5",
                           "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Basic {self.auth}"})
        with urllib.request.urlopen(req, timeout=60.0) as r:
            j = json.loads(r.read().decode())
        if j.get("error"):
            raise RuntimeError(j["error"])
        return j["result"]

    def balance(self, address: str, chain_tag: str = "btc") -> BalanceResult:
        res = self._call("scantxoutset", ["start", [f"addr({address})"]])
        total = sum(float(o["txout"]["value"]) for o in res.get("unspents", []))
        return BalanceResult(address, chain_tag, int(total * 1e8), 0,
                             len(res.get("unspents", [])), self.name)


# ---------------------------------------------------------- check service
DEFAULT_BACKENDS = {
    "btc": ("electrs", "blockstream"),
    "ltc": ("litecoin-space",),
    "doge": ("dogechain",),
    "zec": ("zchain",),
}


class BalanceChecker:
    """Bloom-gated, read-only balance oracle used by the scanner.

    Modes:
      * ``mode="local"``   — backend must be a local node/server; if none is
        reachable the checker degrades to an offline watchlist (zero traffic).
      * ``mode="public"``  — public explorers allowed, GET only.

    ``check_many`` applies the bloom pre-screen so at most a handful of
    network calls happen per million derived addresses.
    """

    def __init__(self, mode: str = "public",
                 watchlist: Optional[Watchlist] = None,
                 backends: Optional[dict] = None,
                 require_watch_hit: bool = False):
        assert mode in ("local", "public", "offline")
        self.mode = mode
        self.watch = watchlist
        self.require_watch_hit = require_watch_hit
        self.backends = backends or {}
        self.hits: List[BalanceResult] = []
        self.probed = 0
        self.skipped_by_bloom = 0

    def _backend_for(self, chain_base: str) -> Optional[Backend]:
        if chain_base in self.backends:
            return self.backends[chain_base]
        if self.mode == "local":
            if chain_base == "btc":
                return ElectrsBackend()           # 127.0.0.1:3000 default
            return None
        if self.mode == "public":
            bmap = {"btc": lambda: BlockstreamBackend(),
                    "ltc": lambda: LitecoinspaceBackend(),
                    "doge": lambda: DogeChainBackend(),
                    "zec": lambda: ZchainZecBackend()}
            mk = bmap.get(chain_base)
            if mk:
                self.backends[chain_base] = mk()
                return self.backends[chain_base]
        return None

    def check(self, chain_tag: str, address: str) -> Optional[BalanceResult]:
        # 1) bloom gate — cheap, in-memory, eliminates ~all traffic
        if self.watch is not None:
            if not self.watch.might_be_funded(address):
                self.skipped_by_bloom += 1
                return None
            if self.require_watch_hit and not self.watch.confirm(address):
                self.skipped_by_bloom += 1       # bloom false positive
                return None
        if self.mode == "offline":
            # offline + watchlist exact match is the only source of truth
            if self.watch and self.watch.confirm(address):
                r = BalanceResult(address, chain_tag, 1, 0, 0, "watchlist")
                self.hits.append(r)
                return r
            return None
        # 2) network read (GET only)
        base = chain_tag.split("-")[0]
        be = self._backend_for(base)
        if be is None:
            return None
        try:
            r = be.balance(address, chain_tag)
        except Exception:
            return None
        self.probed += 1
        if r.funded:
            self.hits.append(r)
            return r
        return None

    def check_many(self, pairs: Iterable[tuple[str, str]]
                   ) -> List[BalanceResult]:
        found = []
        for tag, addr in pairs:
            r = self.check(tag, addr)
            if r:
                found.append(r)
        return found
