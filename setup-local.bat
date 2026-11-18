@echo off
setlocal
cd /d "%~dp0"

if not exist "tools\luau.exe" (
  echo Windows Luau tools are missing; downloading Luau 0.747 Windows binaries...
  where py >nul 2>nul
  if %errorlevel%==0 (
    py -3 fetch_tools_windows.py
  ) else (
    python fetch_tools_windows.py
  )
)

if not exist "tests\baseline\tools" (
  mklink /D "tests\baseline\tools" "..\..\tools" >nul 2>nul
  if errorlevel 1 echo Warning: could not create baseline tools symlink. The web app still works; full self-test may need Developer Mode or Administrator.
)

echo Local Windows setup ready.
echo Start the app with: start-local.bat
exit /b 0
