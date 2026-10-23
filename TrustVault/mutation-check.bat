@echo off
REM Removes each security check one at a time and confirms a test fails every time.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" call setup.bat
".venv\Scripts\python.exe" scripts\mutation_check.py %*
pause
