@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=all"

if /i not "%MODE%"=="all" if /i not "%MODE%"=="portable" if /i not "%MODE%"=="installer" (
    echo Usage: %~nx0 [all^|portable^|installer]
    echo   all       Build portable .exe and, if Inno Setup is installed, the Windows installer ^(default^)
    echo   portable  Build only the standalone portable .exe ^(dist\FirewallMigrationTool.exe^)
    echo   installer Build the --onedir app and Windows Setup installer ^(requires Inno Setup 6^)
    exit /b 1
)

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
        echo Install Python 3.14 or newer and add it to PATH, then retry.
        goto :failed
    )
)

echo Installing/updating backend and desktop packaging dependencies...
"%PYTHON%" -m pip install -e ".[collection]" pyinstaller pywebview
if errorlevel 1 goto :failed

for /f "tokens=3 delims= " %%V in ('findstr /b /c:"version = " pyproject.toml') do set "APP_VERSION=%%~V"
if "%APP_VERSION%"=="" set "APP_VERSION=0.2.1"

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

set "EXTRA_PYINSTALLER_ARGS="
for /f "usebackq delims=" %%D in (`"%PYTHON%" -c "import pathlib, sys; p = pathlib.Path(sys.base_prefix) / 'abi3t-compat' / 'python3t.dll'; print(p if p.is_file() else '')"`) do set "PYTHON3T_DLL=%%D"
if defined PYTHON3T_DLL (
    set "EXTRA_PYINSTALLER_ARGS=--add-binary "%PYTHON3T_DLL%;.""
)

set "COMMON_PYINSTALLER_ARGS=--noconfirm --clean --windowed --noupx --name FirewallMigrationTool --icon "%~dp0scripts\assets\app.ico" --splash "%~dp0scripts\assets\splash.png" --specpath build --add-data "%~dp0src\frontend\dist;frontend_dist" %EXTRA_PYINSTALLER_ARGS% --copy-metadata firewall-migration-tool --collect-submodules fwmigrate --collect-data fwmigrate --collect-data tzdata --collect-all webview --exclude-module gunicorn --exclude-module pytest --exclude-module _pytest --exclude-module pip --exclude-module setuptools --exclude-module wheel --exclude-module webview.platforms.cocoa --exclude-module webview.platforms.gtk --exclude-module webview.platforms.qt --exclude-module webview.platforms.android --exclude-module webview.platforms.cef"

if /i "%MODE%"=="portable" goto :build_portable
if /i "%MODE%"=="all" goto :build_portable
goto :build_installer

:build_portable
echo.
echo Packaging standalone portable executable ^(version %APP_VERSION%^)...
"%PYTHON%" -m PyInstaller --onefile %COMMON_PYINSTALLER_ARGS% scripts\desktop_launcher.py
if errorlevel 1 goto :failed
echo Portable build complete: "%~dp0dist\FirewallMigrationTool.exe"
if /i "%MODE%"=="portable" exit /b 0

:build_installer
set "ISCC="
for %%P in (
    "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    "%ProgramFiles%\Inno Setup 6\ISCC.exe"
    "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
) do (
    if exist "%%~P" (
        set "ISCC=%%~P"
        goto :found_iscc
    )
)
for /f "delims=" %%P in ('where ISCC.exe 2^>nul') do (
    set "ISCC=%%~P"
    goto :found_iscc
)

:found_iscc
if "%ISCC%"=="" (
    echo.
    echo Inno Setup 6 ^(ISCC.exe^) was not found.
    echo Install it with: winget install JRSoftware.InnoSetup
    if /i "%MODE%"=="installer" goto :failed
    echo Skipping Windows installer build ^(portable .exe is ready^).
    exit /b 0
)

echo.
echo Packaging --onedir bundle for installer ^(version %APP_VERSION%^)...
"%PYTHON%" -m PyInstaller --onedir %COMMON_PYINSTALLER_ARGS% scripts\desktop_launcher.py
if errorlevel 1 goto :failed

echo.
echo Building Windows installer...
"%ISCC%" /DAppVersion=%APP_VERSION% "%~dp0scripts\installer\FirewallMigrationTool.iss"
if errorlevel 1 goto :failed

echo.
echo Installer build complete: "%~dp0dist\FirewallMigrationTool-Setup-%APP_VERSION%.exe"
exit /b 0

:failed
echo.
echo Desktop build failed.
exit /b 1
