@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON=%~dp0.venv\Scripts\python.exe"

where node >nul 2>&1
if errorlevel 1 (
    echo Node.js was not found. Install Node.js, then run this file again.
    goto :failed
)
where npm >nul 2>&1
if errorlevel 1 (
    echo npm was not found. Install Node.js with npm, then retry.
    goto :failed
)

if not exist "%PYTHON%" (
    echo Creating the Python virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Install Python 3.14 or newer and add it to PATH, then retry.
        goto :failed
    )
)

echo Installing/updating backend and desktop packaging dependencies...
"%PYTHON%" -m pip install -e ".[collection]" pyinstaller pywebview
if errorlevel 1 goto :failed

echo Building frontend production bundle...
if exist "src\frontend\node_modules" (
    call npm --prefix src\frontend install
) else (
    call npm --prefix src\frontend ci
)
if errorlevel 1 goto :failed
call npm --prefix src\frontend run build
if errorlevel 1 goto :failed

if not exist "src\frontend\dist\index.html" (
    echo Frontend build did not produce src\frontend\dist\index.html.
    goto :failed
)

echo Packaging standalone desktop executable...
"%PYTHON%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --windowed ^
  --noupx ^
  --name "FirewallMigrationTool" ^
  --icon "%~dp0scripts\assets\app.ico" ^
  --splash "%~dp0scripts\assets\splash.png" ^
  --specpath "build" ^
  --add-data "%~dp0src\frontend\dist;frontend_dist" ^
  --collect-submodules fwmigrate ^
  --collect-data tzdata ^
  --collect-all webview ^
  --exclude-module gunicorn ^
  --exclude-module pytest ^
  --exclude-module _pytest ^
  --exclude-module pip ^
  --exclude-module setuptools ^
  --exclude-module wheel ^
  --exclude-module webview.platforms.cocoa ^
  --exclude-module webview.platforms.gtk ^
  --exclude-module webview.platforms.qt ^
  --exclude-module webview.platforms.android ^
  --exclude-module webview.platforms.cef ^
  scripts\desktop_launcher.py
if errorlevel 1 goto :failed

echo.
echo Build complete: "%~dp0dist\FirewallMigrationTool.exe"
exit /b 0

:failed
echo.
echo Desktop build failed.
exit /b 1
