"""Environment introspection for reproducibility reports.

Checks: Python version, availability of Node.js (used by optional real-WASM
experiments), presence of the OS CSPRNG (`secrets`), internet reachability to
GitHub (optional; offline mode must still work), and project paths.
"""
from __future__ import annotations

import platform
import secrets as _secrets
import shutil
import socket
import subprocess
import sys
from typing import Any


def check_python() -> dict[str, Any]:
    return {
        "ok": sys.version_info >= (3, 10),
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "required_min": "3.10",
    }


def check_os_csprng() -> dict[str, Any]:
    try:
        b = _secrets.token_bytes(8)
        return {"ok": len(b) == 8, "provider": "os.urandom via secrets"}
    except Exception as e:  # pragma: no cover - should not happen
        return {"ok": False, "error": str(e)}


def check_node() -> dict[str, Any]:
    path = shutil.which("node")
    if not path:
        return {"ok": False, "note": "node not found; real WASM experiments unavailable"}
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
        return {"ok": out.returncode == 0, "path": path,
                "version": out.stdout.strip()}
    except Exception as e:
        return {"ok": False, "path": path, "error": str(e)}


def check_internet(host: str = "api.github.com", port: int = 443,
                   timeout: float = 5.0) -> dict[str, Any]:
    """Best-effort connectivity probe. Never required for core features."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "host": host}
    except OSError as e:
        return {"ok": False, "host": host, "error": type(e).__name__}


def full_report(include_network: bool = True) -> dict[str, Any]:
    checks = {
        "platform": platform.platform(),
        "python": check_python(),
        "os_csprng": check_os_csprng(),
        "node": check_node(),
    }
    checks["all_required_ok"] = all(
        checks[k]["ok"] for k in ("python", "os_csprng"))
    if include_network:
        checks["internet"] = check_internet()
    return checks
