@echo off
REM Run the automated test suite (SQLite). For PostgreSQL:  set TEST_DATABASE_URL=postgresql://... then run this.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" call setup.bat
".venv\Scripts\python.exe" -m pytest -v
pause
