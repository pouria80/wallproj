"""Wallet Scanner V2 — one-command web GUI server (stdlib only).

Run:  python app.py   →  opens http://localhost:8000
"""
from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "core"))

from scanner import Scanner  # noqa: E402

WEB_DIR = Path(__file__).resolve().parent / "web"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8000
scanner = Scanner()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/status"):
            self._send(200, json.dumps(scanner.status()).encode(), "application/json")
        elif self.path in ("/", "/index.html"):
            self._serve_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
        elif self.path == "/app.js":
            self._serve_file(WEB_DIR / "app.js", "application/javascript; charset=utf-8")
        elif self.path == "/style.css":
            self._serve_file(WEB_DIR / "style.css", "text/css; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("content-length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        route = self.path.split("?")[0]
        ok = True
        if route == "/api/start":
            cfg = {k: v for k, v in data.items() if v is not None}
            scanner.configure(**cfg)
            ok = scanner.start()
        elif route == "/api/stop":
            scanner.stop()
        elif route == "/api/reset":
            scanner.reset()
        elif route == "/api/config":
            scanner.configure(**{k: v for k, v in data.items() if v is not None})
        self._send(200, json.dumps({"ok": ok}).encode(), "application/json")

    def _serve_file(self, path: Path, ctype: str):
        if path.exists():
            self._send(200, path.read_bytes(), ctype)
        else:
            self._send(404, b"missing", "text/plain")


def main():
    url = f"http://localhost:{PORT}"
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Wallet Scanner V2  →  {url}")
    print("Ctrl+C برای توقف")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        scanner.stop()
        srv.shutdown()


if __name__ == "__main__":
    main()
