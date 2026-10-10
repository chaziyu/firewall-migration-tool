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
    echo Creating the Python environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Install Python 3.11 or newer and add it to PATH, then retry.
        goto :failed
    )
    "%PYTHON%" -m pip install -e ".[collection,deployment]"
    if errorlevel 1 goto :failed
)

"%PYTHON%" -c "from fwmigrate.web import create_app; create_app()"
if errorlevel 1 (
    echo Backend startup check failed. See the error above.
    echo To install dependencies, run:
    echo   .venv\Scripts\python.exe -m pip install -e ".[collection,deployment]"
    goto :failed
)

if not exist "src\frontend\node_modules\.bin\vite.cmd" (
    echo Installing frontend dependencies...
    call npm --prefix src\frontend ci
    if errorlevel 1 goto :failed
)

echo Backend:  http://127.0.0.1:5000
echo Frontend: http://127.0.0.1:5000
echo Press Ctrl+C in each server window to stop it.
start "Firewall Migration Backend" cmd /k ""%PYTHON%" -m fwmigrate.main serve --host 127.0.0.1 --port 5000"
if errorlevel 1 goto :failed

cd /d "%~dp0src\frontend"
call npm run dev -- --host 127.0.0.1 --port 5173 --strictPort --open http://127.0.0.1:5000/
if errorlevel 1 goto :failed
exit /b 0

:failed
echo Local startup failed.
pause
exit /b 1
