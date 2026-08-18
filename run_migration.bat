@echo off
echo Starting FortiGate to Palo Alto Migration Web Server...
echo The web interface will be available at http://localhost:5000
echo.
python -m fg2pan.main serve --port 5000
pause
