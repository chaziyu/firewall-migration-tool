@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON=%~dp0.venv\Scripts\python.exe"

if not exist "%PYTHON%" (
    echo Creating the Python environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Install Python 3.11 or newer and add it to PATH, then retry.
        goto :failed
    )
    "%PYTHON%" -m pip install -e ".[collection]"
    if errorlevel 1 goto :failed
)

"%PYTHON%" -c "from fwmigrate.web import create_app; create_app()"
if errorlevel 1 (
    echo Backend startup check failed. See the error above.
    echo To install dependencies, run:
    echo   .venv\Scripts\python.exe -m pip install -e ".[collection]"
    goto :failed
)

if exist "src\frontend\dist\index.html" goto :frontend_ready

where node >nul 2>&1
if errorlevel 1 (
    echo Frontend build ^(src\frontend\dist\index.html^) is missing and Node.js was not found.
    echo Install Node.js or provide a prebuilt src\frontend\dist folder, then run this file again.
    goto :failed
)
where npm >nul 2>&1
if errorlevel 1 (
    echo Frontend build ^(src\frontend\dist\index.html^) is missing and npm was not found.
    goto :failed
)

if not exist "src\frontend\node_modules\.bin\vite.cmd" (
    echo Synchronizing frontend dependencies from the lockfile...
    call npm --prefix src\frontend ci --prefer-offline
    if errorlevel 1 goto :failed
    if not exist "src\frontend\node_modules\.bin\vite.cmd" (
        echo Frontend dependencies failed to install completely ^(vite.cmd missing^).
        echo Try: rmdir /s /q src\frontend\node_modules ^&^& npm cache clean --force ^&^& npm --prefix src\frontend ci
        goto :failed
    )
)

echo Building frontend production bundle...
call npm --prefix src\frontend run build
if errorlevel 1 goto :failed
if not exist "src\frontend\dist\index.html" (
    echo Frontend build did not produce src\frontend\dist\index.html.
    goto :failed
)

:frontend_ready
echo Starting Firewall Migration Tool on http://127.0.0.1:5000/
echo Press Ctrl+C in this window to stop the server.
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "$deadline = (Get-Date).AddSeconds(30); while ((Get-Date) -lt $deadline) { try { $c = [System.Net.Sockets.TcpClient]::new('127.0.0.1', 5000); $c.Close(); Start-Process 'http://127.0.0.1:5000/'; exit 0 } catch { Start-Sleep -Milliseconds 250 } }"
"%PYTHON%" -m fwmigrate.main serve --host 127.0.0.1 --port 5000
if errorlevel 1 goto :failed
exit /b 0

:failed
echo Local startup failed.
pause
exit /b 1
