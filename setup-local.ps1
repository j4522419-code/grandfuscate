$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Invoke-Py {
    param([string[]]$PyArgs)
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 @PyArgs
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python @PyArgs
    } else {
        throw "Python 3.13 was not found. Install it from https://www.python.org/downloads/windows/ and tick 'Add Python to PATH'."
    }
}

if (-not (Test-Path "tools\luau.exe")) {
    Write-Host "Windows Luau tools are missing; downloading Luau 0.747 Windows binaries..."
    Invoke-Py @("fetch_tools_windows.py")
}

$link = Join-Path $PSScriptRoot "tests\baseline\tools"
if (-not (Test-Path $link)) {
    try {
        New-Item -ItemType SymbolicLink -Path $link -Target (Resolve-Path "tools").Path -ErrorAction Stop | Out-Null
        Write-Host "restored tests\baseline\tools -> tools"
    } catch {
        Write-Warning "Could not create tests\baseline\tools symlink. The local web app still works; the full self-test may need Developer Mode or Administrator."
    }
}

Write-Host "Local Windows setup ready."
Write-Host "Start the app: powershell -ExecutionPolicy Bypass -File .\start-local.ps1"
Write-Host "Or in CMD: start-local.bat"
