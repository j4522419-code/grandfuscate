@echo off
setlocal
cd /d "%~dp0"

set "PORT=8000"
set "OBF_MAX_SOURCE=10485760"
set "OBF_MAX_BODY=16777216"
set "OBF_TIMEOUT=300"

if not exist "tools\luau.exe" (
  echo Windows Luau tools are missing. Run setup-local.bat first.
  exit /b 1
)

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m obf.web
) else (
  python -m obf.web
)
exit /b %errorlevel%
