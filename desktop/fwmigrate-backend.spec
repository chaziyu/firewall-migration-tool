# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).parent

datas = [(str(ROOT / 'src' / 'fwmigrate' / 'static'), 'fwmigrate/static')]
binaries = []
hiddenimports = ['clr', 'clr_loader', 'pythonnet']

tmp_ret = collect_all('fwmigrate')
datas += [item for item in tmp_ret[0] if not item[1].replace('\\', '/').startswith('fwmigrate/ai_runtime/')]
binaries += [item for item in tmp_ret[1] if not item[1].replace('\\', '/').startswith('fwmigrate/ai_runtime/')]
hiddenimports += tmp_ret[2]

a = Analysis(
    [str(ROOT / 'src' / 'fwmigrate' / 'desktop_server.py')],
    pathex=[str(ROOT / 'src')],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['webview'],
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
    name='fwmigrate-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
