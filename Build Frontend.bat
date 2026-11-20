@echo off
setlocal EnableExtensions
cd /d "%~dp0"

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

if not exist "src\frontend\node_modules" (
    echo Installing frontend dependencies...
    call npm --prefix src\frontend install
    if errorlevel 1 goto :failed
)

echo Building frontend production bundle...
call npm --prefix src\frontend run build
if errorlevel 1 goto :failed

if not exist "src\frontend\dist\index.html" (
    echo Frontend build did not produce src\frontend\dist\index.html.
    goto :failed
)

echo.
echo Frontend build complete: "%~dp0src\frontend\dist"
echo You can now run "Start Local.bat".
pause
exit /b 0

:failed
echo.
echo Frontend build failed.
pause
exit /b 1
