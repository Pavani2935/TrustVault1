@echo off
REM Start TrustVault locally on http://127.0.0.1:8000 (SQLite, demo data seeded on first run)
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo First run: setting up ...
  call setup.bat
)
set "PORT=8000"
if not "%~1"=="" set "PORT=%~1"
REM open the browser a few seconds after the server starts
start "" /b cmd /c "timeout /t 4 /nobreak >nul & start "" http://127.0.0.1:%PORT%/login"
echo TrustVault is starting on http://127.0.0.1:%PORT%  (close this window to stop it)
".venv\Scripts\python.exe" -m trustvault serve --host 127.0.0.1 --port %PORT%
pause
