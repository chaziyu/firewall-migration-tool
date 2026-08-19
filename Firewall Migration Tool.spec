# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('src/fg2pan/templates', 'fg2pan/templates'), ('src/fg2pan/static', 'fg2pan/static'), ('bin/terraform.exe', 'bin')]
binaries = []
hiddenimports = ['clr', 'clr_loader', 'pythonnet']
tmp_ret = collect_all('fg2pan')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['src/fg2pan/main.py'],
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
    icon='src/fg2pan/static/app_icon.ico',
)
