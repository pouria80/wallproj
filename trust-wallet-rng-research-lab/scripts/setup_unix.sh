#!/usr/bin/env bash
# Setup helper for Linux/macOS. Run from repo root: bash scripts/setup_unix.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
$PY -m venv .venv
source .venv/bin/activate
pip install --upgrade pip >/dev/null
pip install -r requirements-dev.txt
echo "OK. Activate with: source .venv/bin/activate"
echo "Run tests: python -m pytest -q   |   CLI: PYTHONPATH=src python -m rng_research.cli info"
