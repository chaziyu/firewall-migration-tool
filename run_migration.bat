@echo off
setlocal
cd /d "%~dp0"

echo Building the React frontend...
where npm >nul 2>nul
if errorlevel 1 (
  echo Node.js and npm are required to build the frontend. Install the Node.js LTS release and try again.
  pause
  exit /b 1
)

pushd "%~dp0src\frontend"
if not exist "node_modules" (
  echo Installing frontend dependencies...
  call npm ci
  if errorlevel 1 goto frontend_failed
)

call npm run build
if errorlevel 1 goto frontend_failed
popd

echo Starting Firewall Migration Tool Web Server...
echo The web interface will be available at http://localhost:5000
echo.
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
python -m fwmigrate.main serve --port 5000
set "SERVER_EXIT=%ERRORLEVEL%"
pause
exit /b %SERVER_EXIT%

:frontend_failed
popd
echo.
echo Frontend build failed. The web server was not started.
pause
exit /b 1
