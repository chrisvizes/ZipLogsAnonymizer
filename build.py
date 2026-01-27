#!/usr/bin/env python3
"""
Build script to create a standalone executable for ZipLogsAnonymizer.

Usage:
    python build.py

This will create a single .exe file in the 'dist' folder that can be
distributed to users without Python installed.

Requirements:
    pip install pyinstaller
"""

import subprocess
import sys
import shutil
from pathlib import Path


def build():
    """Build the standalone executable."""
    print("=" * 60)
    print("Building ZipLogsAnonymizer Executable")
    print("=" * 60)

    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("Error: PyInstaller not found.")
        print("Install it with: pip install pyinstaller")
        sys.exit(1)

    # Clean previous builds
    for folder in ["build", "dist"]:
        if Path(folder).exists():
            print(f"Cleaning {folder}/...")
            shutil.rmtree(folder)

    # Determine platform-specific separator for --add-data
    # Windows uses ';', Mac/Linux use ':'
    separator = ";" if sys.platform == "win32" else ":"

    # PyInstaller command
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--onefile",              # Single executable
        "--windowed",             # No console window (GUI app)
        "--name", "ZipLogsAnonymizer",
        "--add-data", f"pattern_matcher.py{separator}.",  # Include pattern_matcher module
        "--add-data", f"anonymizer.py{separator}.",       # Include anonymizer module
        # Hidden imports that PyInstaller might miss
        "--hidden-import", "pattern_matcher",
        "--hidden-import", "anonymizer",
        "gui.py"
    ]

    print("\nRunning PyInstaller...")
    print(f"Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd)

    if result.returncode == 0:
        # Executable name varies by platform
        if sys.platform == "win32":
            exe_path = Path("dist/ZipLogsAnonymizer.exe")
        else:
            exe_path = Path("dist/ZipLogsAnonymizer")

        if exe_path.exists():
            size_mb = exe_path.stat().st_size / 1024 / 1024
            print("\n" + "=" * 60)
            print("BUILD SUCCESSFUL!")
            print("=" * 60)
            print(f"\nExecutable: {exe_path.absolute()}")
            print(f"Size: {size_mb:.1f} MB")
            print("\nYou can now distribute this file to your colleagues.")
            print("They just need to double-click it to run - no Python required!")
        else:
            print("\nWarning: Build completed but executable not found.")
    else:
        print("\n" + "=" * 60)
        print("BUILD FAILED")
        print("=" * 60)
        print("Check the output above for errors.")
        sys.exit(1)


if __name__ == "__main__":
    build()
