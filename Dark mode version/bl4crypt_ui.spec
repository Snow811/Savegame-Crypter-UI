# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for BL4 Crypt UI (PyQt5 Version)

import sys
from PyInstaller.utils.hooks import collect_data_files

# Collect PyQt5 data files and plugins
pyqt5_datas = collect_data_files('PyQt5')

a = Analysis(
    ['bl4crypt_ui.py'],
    pathex=[],
    binaries=[],
    datas=pyqt5_datas,
    hiddenimports=[
        'PyQt5.QtCore',
        'PyQt5.QtGui', 
        'PyQt5.QtWidgets',
        'PyQt5.sip',
        'sip',
        'subprocess',
        'os',
        'sys'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'cv2',
        'scipy'
    ],
    noarchive=False,
    optimize=2,
)

# Remove duplicate entries and optimize
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='BL4_Crypt_UI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path here if you have one: icon='icon.ico'
    version_info=None,
    manifest=None,
    uac_admin=False,
    uac_uiaccess=False,
)
