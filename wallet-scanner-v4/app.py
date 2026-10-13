"""Wallet Scanner V4 — parallel full-coverage seed-space scanner (stdlib only).

Run:  python app.py [port]   →  http://localhost:8000

Backend for the Persian RTL dashboard. All state lives in
core.search_engine.SearchEngine (multiprocessing pool + checkpointed cursor +
RPC balance workers). Endpoints:

  GET  /api/status     -> full engine status JSON (progress, rate, ETA, funded, logs)
  GET  /api/download   -> funded_wallets.jsonl as an attachment
  POST /api/start      {start_seed,end_seed,num_workers,chunk_size,threshold_eth,
                        threshold_usdt,live_rpc}
  POST /api/pause      / /api/resume / /api/stop / /api/reset
  POST /api/config     same keys as start, applied without restarting

SAFETY: research/defensive tooling for the historical CVE-2023-31290 Trust
Wallet RNG flaw; simulation-first (derive_only default). No attack tooling.
"""
from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))

from search_engine import SearchEngine, HITS_FILE  # noqa: E402

WEB_DIR = ROOT / "web"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8000
engine = SearchEngine()

_INT_KEYS = {"start_seed", "end_seed", "num_workers", "chunk_size"}
_FLOAT_KEYS = {"threshold_eth", "threshold_usdt"}
_BOOL_KEYS = {"live_rpc"}


def _apply_cfg(data: dict) -> None:
    kw: dict = {}
    for k in _INT_KEYS:
        if data.get(k) not in (None, ""):
            kw[k] = int(data[k])
    for k in _FLOAT_KEYS:
        if data.get(k) not in (None, ""):
            kw[k] = float(data[k])
    if "live_rpc" in data and data["live_rpc"] is not None:
        # GUI flag maps onto engine.derive_only (inverse meaning)
        kw["derive_only"] = not bool(data["live_rpc"])
    if kw:
        engine.configure(**kw)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    # ------------------------------------------------------------ plumbing
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")

    # ---------------------------------------------------------------- GET
    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        if p.startswith("/api/status"):
            self._json(engine.status())
        elif p.startswith("/api/download"):
            if HITS_FILE.exists() and HITS_FILE.stat().st_size > 0:
                body = HITS_FILE.read_bytes()
                self.send_response(200)
                self.send_header("content-type",
                                 "application/x-ndjson; charset=utf-8")
                self.send_header("content-disposition",
                                 'attachment; filename="funded_wallets.jsonl"')
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send(404, b"no funded wallets yet", "text/plain")
        elif p in ("/", "/index.html"):
            self._serve_file(WEB_DIR / "index.html",
                             "text/html; charset=utf-8")
        elif p == "/app.js":
            self._serve_file(WEB_DIR / "app.js",
                             "application/javascript; charset=utf-8")
        elif p == "/style.css":
            self._serve_file(WEB_DIR / "style.css", "text/css; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    # --------------------------------------------------------------- POST
    def do_POST(self):  # noqa: N802
        try:
            n = int(self.headers.get("content-length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            data = {}
        route = self.path.split("?")[0]
        ok = True
        if route == "/api/start":
            _apply_cfg(data)
            ok = engine.start()
        elif route == "/api/pause":
            engine.pause()
        elif route == "/api/resume":
            engine.resume()
        elif route == "/api/stop":
            engine.stop()
        elif route == "/api/reset":
            engine.reset()
        elif route == "/api/config":
            _apply_cfg(data)
        else:
            self._send(404, b"not found", "text/plain")
            return
        self._json({"ok": ok})

    def _serve_file(self, path: Path, ctype: str):
        if path.exists():
            self._send(200, path.read_bytes(), ctype)
        else:
            self._send(404, b"missing static asset: " + path.name.encode(),
                       "text/plain")


def main():
    url = f"http://localhost:{PORT}"
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Wallet Scanner V4  →  {url}")
    print("Ctrl+C برای توقف")
    try:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    except Exception:
        pass  # headless environments simply have no browser
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        engine.stop()
        srv.shutdown()


if __name__ == "__main__":
    main()
