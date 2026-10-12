# Setup helper for Windows PowerShell. From repo root: .\scripts\setup_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements-dev.txt
Write-Host "OK. Tests: .\scripts\run_tests.ps1  CLI: `$env:PYTHONPATH='src'; python -m rng_research.cli info"
