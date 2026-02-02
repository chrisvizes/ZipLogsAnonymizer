#!/usr/bin/env python3
"""
Build script to create a standalone executable for ZipLogsAnonymizer.

Usage:
    python build.py              # Build with Rust acceleration (if available)
    python build.py --pure-python  # Build without Rust (pure Python mode)

This will create a single .exe file in the 'dist' folder that can be
distributed to users without Python installed.

Requirements:
    pip install pyinstaller
    pip install maturin  (optional, for Rust acceleration)

For Rust acceleration:
    1. Install Rust: https://rustup.rs/
    2. pip install maturin
    3. The build script will automatically compile the Rust extension
"""

import argparse
import subprocess
import sys
import shutil
import zipfile
from pathlib import Path


def get_rust_env() -> tuple[dict, Path] | None:
    """Get environment with Rust toolchain in PATH and the cargo bin path.

    Returns (modified environment dict, cargo_bin_path), or None if Rust not found.
    """
    import os

    # Check common Rust installation locations
    cargo_bin_paths = [
        Path.home() / ".cargo" / "bin",  # Default rustup location
        Path("C:/Users") / os.environ.get("USERNAME", "") / ".cargo" / "bin",
    ]

    env = os.environ.copy()

    for cargo_bin in cargo_bin_paths:
        rustc_path = cargo_bin / ("rustc.exe" if sys.platform == "win32" else "rustc")
        if rustc_path.exists():
            # Add cargo bin to PATH
            env["PATH"] = str(cargo_bin) + os.pathsep + env.get("PATH", "")
            return env, cargo_bin

    # Rust not found in common locations, check if already in PATH
    try:
        result = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            return env, None  # Rust is in PATH, no specific bin dir needed
    except FileNotFoundError:
        pass

    return None


def build_rust_extension() -> Path | None:
    """Build the Rust extension if source is available.

    Returns the path to the built wheel, or None if not available.
    """
    rust_dir = Path("rust_core")
    if not rust_dir.exists():
        print("Rust source not found, using pure Python mode")
        return None

    # Check if maturin is installed
    try:
        result = subprocess.run(
            [sys.executable, "-m", "maturin", "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("maturin not installed, using pure Python mode")
            print("Install with: pip install maturin")
            return None
        print(f"maturin version: {result.stdout.strip()}")
    except FileNotFoundError:
        print("maturin not found, using pure Python mode")
        return None

    # Get environment with Rust in PATH
    rust_result = get_rust_env()
    if rust_result is None:
        print("Rust not found, using pure Python mode")
        print("Install from: https://rustup.rs/")
        return None

    rust_env, cargo_bin = rust_result

    # Determine rustc command - use full path on Windows if we found the bin dir
    if cargo_bin is not None:
        rustc_cmd = str(cargo_bin / ("rustc.exe" if sys.platform == "win32" else "rustc"))
    else:
        rustc_cmd = "rustc"

    # Verify Rust version
    result = subprocess.run(
        [rustc_cmd, "--version"], capture_output=True, text=True, env=rust_env
    )
    if result.returncode != 0:
        print("Rust not working correctly, using pure Python mode")
        return None
    print(f"Rust version: {result.stdout.strip()}")

    print("\nBuilding Rust extension...")
    result = subprocess.run(
        [sys.executable, "-m", "maturin", "build", "--release"],
        cwd=rust_dir,
        capture_output=True,
        text=True,
        env=rust_env,
    )

    if result.returncode != 0:
        print(f"Rust build failed:\n{result.stderr}")
        return None

    # Find the built wheel
    wheels = list((rust_dir / "target" / "wheels").glob("*.whl"))
    if wheels:
        print(f"Rust extension built: {wheels[0].name}")
        return wheels[0]

    print("No wheel found after Rust build")
    return None


def extract_rust_binary(wheel_path: Path) -> list[tuple[str, str]]:
    """Extract the Rust binary from the wheel for PyInstaller.

    Returns a list of (source, destination) tuples for --add-binary.
    """
    binaries = []
    rust_dist = Path("rust_dist")
    rust_dist.mkdir(exist_ok=True)

    with zipfile.ZipFile(wheel_path, "r") as zf:
        for name in zf.namelist():
            # Look for the compiled extension (.pyd on Windows, .so on Unix)
            if name.endswith((".pyd", ".so")) and "anonymizer_core" in name:
                zf.extract(name, rust_dist)
                extracted_path = rust_dist / name
                binaries.append((str(extracted_path), "."))
                print(f"Extracted Rust binary: {name}")

    return binaries


def build(pure_python: bool = False):
    """Build the standalone executable."""
    print("=" * 60)
    print("Building ZipLogsAnonymizer Executable")
    if pure_python:
        print("(Pure Python mode - no Rust acceleration)")
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
    for folder in ["build", "dist", "rust_dist"]:
        if Path(folder).exists():
            print(f"Cleaning {folder}/...")
            shutil.rmtree(folder)

    # Try to build Rust extension (unless pure Python mode)
    rust_binaries = []
    if not pure_python:
        wheel_path = build_rust_extension()
        if wheel_path:
            rust_binaries = extract_rust_binary(wheel_path)

    # Determine platform-specific separator for --add-data
    # Windows uses ';', Mac/Linux use ':'
    separator = ";" if sys.platform == "win32" else ":"

    # PyInstaller command
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",  # Single executable
        "--windowed",  # No console window (GUI app)
        "--name",
        "ZipLogsAnonymizer",
        "--add-data",
        f"pattern_matcher.py{separator}.",  # Include pattern_matcher module
        "--add-data",
        f"anonymizer.py{separator}.",  # Include anonymizer module
        # Hidden imports that PyInstaller might miss
        "--hidden-import",
        "pattern_matcher",
        "--hidden-import",
        "anonymizer",
    ]

    # Add Rust binaries if available
    if rust_binaries:
        cmd.extend(["--hidden-import", "anonymizer_core"])
        for src, dst in rust_binaries:
            cmd.extend(["--add-binary", f"{src}{separator}{dst}"])
        print(f"\nIncluding Rust acceleration ({len(rust_binaries)} binary)")
    else:
        print("\nBuilding without Rust acceleration (pure Python)")

    cmd.append("gui.py")

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
            if rust_binaries:
                print("Mode: Rust-accelerated (300+ MB/s)")
            else:
                print("Mode: Pure Python (20-60 MB/s)")
        else:
            print("\nWarning: Build completed but executable not found.")
    else:
        print("\n" + "=" * 60)
        print("BUILD FAILED")
        print("=" * 60)
        print("Check the output above for errors.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build ZipLogsAnonymizer executable")
    parser.add_argument(
        "--pure-python",
        action="store_true",
        help="Build without Rust acceleration (pure Python mode)",
    )
    args = parser.parse_args()
    build(pure_python=args.pure_python)
