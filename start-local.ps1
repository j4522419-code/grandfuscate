$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:PORT = "8000"
$env:OBF_MAX_SOURCE = "10485760"
$env:OBF_MAX_BODY = "16777216"
$env:OBF_TIMEOUT = "300"

if (-not (Test-Path "tools\luau.exe")) {
    throw "Windows Luau tools are missing. Run: powershell -ExecutionPolicy Bypass -File .\setup-local.ps1"
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -m obf.web
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python -m obf.web
} else {
    throw "Python 3.13 was not found. Install it from https://www.python.org/downloads/windows/ and tick 'Add Python to PATH'."
}
