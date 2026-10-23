@echo off
REM ============================================================
REM  TrustVault - one-time setup on Windows
REM  Creates .venv, installs dependencies, creates .env secrets.
REM ============================================================
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo [ERROR] Python 3.10 or newer is required.
  echo         Install it from https://www.python.org/downloads/windows/
  echo         and tick "Add python.exe to PATH" in the installer.
  pause
  exit /b 1
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
  echo [ERROR] Python 3.10 or newer is required. Found:
  %PY% --version
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment in .venv ...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Could not create the virtual environment.
    pause
    exit /b 1
  )
)

echo Installing dependencies ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-dev.txt
if errorlevel 1 (
  echo [ERROR] Dependency installation failed. Check your internet connection and try again.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" scripts\make_env.py

echo.
echo Setup complete.
echo   run.bat             start TrustVault at http://127.0.0.1:8000
echo   test.bat            run the automated security tests
echo   mutation-check.bat  prove the tests catch removed security checks
echo.
pause
