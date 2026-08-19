@echo off
echo Starting Firewall Migration Tool Web Server...
echo The web interface will be available at http://localhost:5000
echo.
set PYTHONPATH=%~dp0src;%PYTHONPATH%
python -m fwmigrate.main serve --port 5000
pause
