@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "IMAGE=firewall-migration-tool:local"
set "CONTAINER=fwmigrate-local"
set "URL=http://localhost:5000"

where docker >nul 2>&1
if errorlevel 1 (
    echo Docker CLI was not found. Install Docker Desktop, then run this file again.
    pause
    exit /b 1
)

docker info >nul 2>&1
if errorlevel 1 (
    echo Docker Desktop is not running. Start it, wait until it is ready, then retry.
    pause
    exit /b 1
)

set "RUNNING="
for /f "delims=" %%N in ('docker ps --filter "name=^/%CONTAINER%$" --format "{{.Names}}"') do set "RUNNING=%%N"
if defined RUNNING (
    echo The container is already running at %URL%.
    echo To rebuild it, stop and remove it with: docker stop %CONTAINER% ^& docker rm %CONTAINER%
    start "" "%URL%"
    exit /b 0
)

set "EXISTING="
for /f "delims=" %%N in ('docker ps -a --filter "name=^/%CONTAINER%$" --format "{{.Names}}"') do set "EXISTING=%%N"
if defined EXISTING docker rm "%CONTAINER%" >nul

echo Building %IMAGE%...
docker build --tag "%IMAGE%" .
if errorlevel 1 goto :failed

if not defined FWMIGRATE_WEB_PASSWORD (
    set /p "FWMIGRATE_WEB_PASSWORD=Choose a local web password: "
)
if not defined FWMIGRATE_WEB_PASSWORD (
    echo A non-empty web password is required.
    goto :failed
)

echo Starting the web application...
docker run --detach --name "%CONTAINER%" --publish 5000:5000 --env FWMIGRATE_WEB_USERNAME=fwmigrate --env FWMIGRATE_WEB_PASSWORD "%IMAGE%" >nul
if errorlevel 1 goto :failed

set "HEALTH="
for /l %%I in (1,1,60) do (
    for /f "delims=" %%S in ('docker inspect --format "{{.State.Health.Status}}" %CONTAINER%') do set "HEALTH=%%S"
    if "!HEALTH!"=="healthy" goto :ready
    if "!HEALTH!"=="unhealthy" goto :unhealthy
    timeout /t 2 /nobreak >nul
)
echo Container did not become healthy within 2 minutes.
goto :failed

:unhealthy
echo The container's health check failed. Recent logs:
docker logs --tail 40 "%CONTAINER%"
pause
exit /b 1

:ready
echo The application is ready at %URL%.
echo Sign in with username fwmigrate and the password you entered.
start "" "%URL%"
exit /b 0

:failed
echo Docker could not start the application. Recent logs:
docker logs --tail 40 "%CONTAINER%" 2>nul
pause
exit /b 1
