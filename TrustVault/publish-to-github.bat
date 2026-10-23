@echo off
REM ============================================================================
REM  Push this folder to a NEW, EMPTY GitHub repository, then open Render's
REM  one-click Blueprint deploy for it.
REM
REM  Usage:   publish-to-github.bat https://github.com/YOUR-NAME/trustvault.git
REM  Needs:   Git for Windows (https://git-scm.com/download/win), signed in to GitHub.
REM ============================================================================
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: publish-to-github.bat https://github.com/YOUR-NAME/trustvault.git
  echo Create an empty public repository on github.com first ^(no README, no .gitignore^).
  pause
  exit /b 1
)
where git >nul 2>nul || (
  echo [ERROR] Git is not installed. Get it from https://git-scm.com/download/win
  pause
  exit /b 1
)
set "REPO=%~1"

set "GITMAIL="
for /f "delims=" %%e in ('git config user.email 2^>nul') do set "GITMAIL=%%e"
if not defined GITMAIL (
  echo [ERROR] Tell Git who you are first, then run this again:
  echo   git config --global user.name "Your Name"
  echo   git config --global user.email "you@example.com"
  pause
  exit /b 1
)

if not exist ".git" (
  git init -b main
)
git add -A
git commit -m "TrustVault: hardened document vault with audit trail" || echo Nothing new to commit.
git remote remove origin >nul 2>nul
git remote add origin "%REPO%"
git push -u origin main
if errorlevel 1 (
  echo [ERROR] Push failed. Check the repository URL and that you are signed in to GitHub.
  pause
  exit /b 1
)

set "WEB=%REPO:.git=%"
echo.
echo Pushed. Opening Render to deploy the Blueprint (render.yaml) ...
start "" "https://render.com/deploy?repo=%WEB%"
pause
