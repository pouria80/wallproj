#!/usr/bin/env python3
"""wallet-tool v5.1 — admin web server (binds 127.0.0.1 ONLY).

Run:  python app.py [port]      →  http://127.0.0.1:8777  (default 8777)

REST API consumed by web/ (Persian RTL dashboard):

  GET  /                     → web/index.html (static from ./web)
  GET  /api/status           → engine status + stats + fingerprint + plan
  GET  /api/hits             → recorded findings (secrets redacted)
  GET  /api/config           → current ScanConfig as JSON
  POST /api/start            {vuln,mode,start_ms,stop_ms,stride,batch,coins,
                              styles,naddr,max_candidates,stop_on_hit,balance,
                              watchlist_path,known_phrase,buckets,parity,
                              auto_fingerprint,fingerprint_sample_hex,min_sat,
                              mt_seed_lo,mt_seed_hi}
  POST /api/stop
  POST /api/fingerprint      {"sample_hex": "..."} → classify a byte stream
  GET  /api/download         → hits.jsonl attachment (redacted)

SAFETY
  * Binds 127.0.0.1 — never exposed on the network.
  * Balance checking is READ-ONLY; no tx-building code exists in this repo.
  * Private keys / mnemonics are NEVER served over HTTP; the GUI only ever
    sees `Finding.public_dict()`.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))

import fingerprint as fpmod                       # noqa: E402
from balance import BalanceChecker, Watchlist     # noqa: E402
from scanner import ScanConfig, ScanEngine, Finding  # noqa: E402

WEB_DIR = ROOT / "web"
STATE_DIR = ROOT / "state"
HITS_FILE = STATE_DIR / "hits.jsonl"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8777

_lock = threading.Lock()
_engine: ScanEngine | None = None
_checker: BalanceChecker | None = None
_logs: list[str] = []


def log(msg: str) -> None:
    stamp = time.strftime("%H:%M:%S")
    _logs.append(f"[{stamp}] {msg}")
    del _logs[:-200]


# ------------------------------------------------------------------ config io
def cfg_from_payload(data: dict) -> ScanConfig:
    def _ms(v, default=0):
        if v in (None, ""):
            return default
        s = str(v)
        if s.isdigit():
            return int(s)
        fmt = "%Y-%m-%dT%H:%M" if "T" in s else "%Y-%m-%d"
        return int(time.mktime(time.strptime(s, fmt)) * 1000)

    buckets = data.get("buckets")
    if isinstance(buckets, str):
        buckets = tuple(int(x) for x in buckets.replace(",", " ").split()) \
            or None
    elif isinstance(buckets, list):
        buckets = tuple(buckets) or None
    styles = data.get("styles")
    if isinstance(styles, str):
        styles = tuple(styles.replace(",", " ").split()) or None
    coins = data.get("coins") or "btc"
    if isinstance(coins, str):
        coins = tuple(c for c in coins.replace(",", " ").split() if c)
    return ScanConfig(
        vuln=data.get("vuln", "randstorm"),
        mode=data.get("mode", "direct"),
        t_start_ms=_ms(data.get("start"), 0),
        t_stop_ms=_ms(data.get("stop"), 0),
        stride_ms=int(data.get("stride", 1) or 1),
        lcg_variant=data.get("lcg_variant", "java"),
        coins=tuple(coins),
        styles=styles,
        naddr=int(data.get("naddr", 1) or 1),
        batch=int(data.get("batch", 4096) or 4096),
        max_candidates=int(data.get("max_candidates", 0) or 0),
        stop_on_hit=bool(data.get("stop_on_hit", False)),
        known_phrase=(data.get("known_phrase") or "").strip(),
        auto_fingerprint=bool(data.get("auto_fingerprint", False)),
        fingerprint_sample_hex=(data.get("fingerprint_sample_hex") or
                                "").strip(),
        buckets=buckets,
        parity=data.get("parity", None) if data.get("parity") in (0, 1,
               "0", "1") else None,
        min_sat=int(data.get("min_sat", 1) or 1),
        mt_seed_lo=int(data.get("mt_seed_lo", 0) or 0),
        mt_seed_hi=int(data.get("mt_seed_hi", 0) or 0),
    )


def make_checker(cfg: ScanConfig, data: dict) -> BalanceChecker:
    wl = None
    wpath = data.get("watchlist_path") or ""
    if wpath and os.path.exists(wpath):
        wl = Watchlist.load(wpath)
        log(f"watchlist loaded: {len(wl.addresses)} addresses")
    mode = data.get("balance", "offline")
    if mode not in ("local", "public", "offline"):
        mode = "offline"
    return BalanceChecker(mode=mode, watchlist=wl,
                          require_watch_hit=(mode == "public" and
                                             wl is not None))


# -------------------------------------------------------------------- record
def record_hit(f: Finding) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    with open(HITS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(f.public_dict()) + "\n")


# ------------------------------------------------------------------- handlers
class Handler(BaseHTTPRequestHandler):
    server_version = "wallettool/5.1"

    def log_message(self, fmt, *args):       # quiet
        pass

    # -- helpers --------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype="application/json",
              extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    # -- GET --------------------------------------------------------------
    def do_GET(self):
        global _engine
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._static("index.html")
        if path in ("/style.css", "/app.js"):
            return self._static(path.lstrip("/"))
        if path == "/api/status":
            with _lock:
                eng = _engine
            if eng is None:
                return self._json({"running": False, "stats": None,
                                   "findings": [], "logs": _logs[-40:],
                                   "note": "no scan started"})
            st = eng.stats
            st.elapsed = (time.time() - st.started) if eng.running \
                else st.elapsed
            return self._json({
                "running": eng.running,
                "config": {k: v for k, v in eng.cfg.__dict__.items()},
                "stats": {**st.__dict__, "rate": st.rate()},
                "coverage_note": eng.stats_extra_note,
                "prune_plan": eng.prune_plan.as_dict(),
                "fingerprint": (eng.fingerprint_report.as_dict()
                                if eng.fingerprint_report else None),
                "findings": [f.public_dict() for f in eng.findings],
                "logs": _logs[-40:],
            })
        if path == "/api/hits":
            rows = []
            if HITS_FILE.exists():
                with open(HITS_FILE, encoding="utf-8") as fh:
                    for ln in fh:
                        try:
                            rows.append(json.loads(ln))
                        except Exception:
                            pass
            return self._json({"hits": rows})
        if path == "/api/download":
            body = (HITS_FILE.read_bytes()
                    if HITS_FILE.exists() else b"")
            return self._send(200, body, "application/x-ndjson",
                              {"Content-Disposition":
                               "attachment; filename=hits_redacted.jsonl"})
        if path == "/api/config":
            with _lock:
                eng = _engine
            if eng is None:
                return self._json({})
            return self._json(
                {k: v for k, v in eng.cfg.__dict__.items()})
        self._send(404, b'{"error":"not found"}')

    def _static(self, name: str):
        p = WEB_DIR / name
        if not p.exists():
            return self._send(404, b'{"error":"missing web file"}')
        ctype = ("text/html; charset=utf-8" if name.endswith(".html")
                 else "text/css" if name.endswith(".css")
                 else "application/javascript")
        self._send(200, p.read_bytes(), ctype)

    # -- POST -------------------------------------------------------------
    def do_POST(self):
        global _engine, _checker
        path = self.path.split("?")[0]
        data = self._read_body()
        if path == "/api/start":
            return self._start(data)
        if path == "/api/stop":
            with _lock:
                eng = _engine
            if eng and eng.running:
                eng.stop()
                log("stop requested")
                return self._json({"ok": True})
            return self._json({"ok": False, "error": "not running"})
        if path == "/api/fingerprint":
            hexs = (data.get("sample_hex") or "").strip()
            try:
                buf = bytes.fromhex(hexs)
            except ValueError:
                return self._json({"error": "invalid hex"}, 400)
            rep = fpmod.classify_stream(buf)
            return self._json(rep.as_dict())
        self._send(404, b'{"error":"not found"}')

    def _start(self, data: dict):
        global _engine, _checker
        with _lock:
            if _engine and _engine.running:
                return self._json({"ok": False,
                                   "error": "scan already running"}, 409)
            try:
                cfg = cfg_from_payload(data)
            except Exception as e:
                return self._json({"ok": False, "error": f"config: {e}"}, 400)
            _checker = make_checker(cfg, data)
            _engine = ScanEngine(cfg, _checker)

            def on_hit(f):
                record_hit(f)
                log(f"HIT {f.source} {f.chain_tag} {f.address} "
                    f"bal={f.balance_sat}")

            _engine.on_hit = on_hit
            try:
                _engine.start()
            except ValueError as e:          # empty window / bad range
                _engine = None
                return self._json({"ok": False, "error": str(e)}, 400)
            tag = "REDUCED-COVERAGE" if _engine.stats.reduced_coverage \
                else "full coverage"
            log(f"scan started ({cfg.vuln}/{cfg.mode}, {tag})")
            return self._json({"ok": True, "coverage_note":
                               _engine.stats_extra_note})


def main():
    # SECURITY: hard-bind loopback.  PORT from argv, host fixed.
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"wallet-tool v5.1 admin UI → http://127.0.0.1:{PORT}  (Ctrl+C to quit)")
    log(f"server up on 127.0.0.1:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with _lock:
            if _engine and _engine.running:
                _engine.stop()
        srv.shutdown()


if __name__ == "__main__":
    main()
