# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

datas = [('src/fwmigrate/templates', 'fwmigrate/templates'), ('src/fwmigrate/static', 'fwmigrate/static')]
binaries = []
runtime_dir = Path('src/fwmigrate/ai_runtime/windows-x64')
runtime_server = runtime_dir / 'llama-server.exe'
if not runtime_server.is_file():
    raise SystemExit('Run python scripts/prepare_ai_runtime.py before building the desktop application')
binaries += [(str(path), 'fwmigrate/ai_runtime/windows-x64')
             for path in runtime_dir.iterdir() if path.suffix.casefold() in {'.exe', '.dll'}]
datas += [(str(path), 'fwmigrate/ai_runtime/windows-x64')
          for path in runtime_dir.iterdir() if path.name in {'runtime-manifest.json', 'THIRD-PARTY-NOTICES.txt'}
          or path.name.startswith('LICENSE')]
hiddenimports = ['clr', 'clr_loader', 'pythonnet']
tmp_ret = collect_all('fwmigrate')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['src/fwmigrate/main.py'],
    pathex=['src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Firewall Migration Tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['src/fwmigrate/static/app_icon.ico'],
)
