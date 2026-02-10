#!/usr/bin/env python3
"""
Shared utility to ensure the Rust anonymizer_core extension is available.

If missing and not running as a frozen executable, attempts to build it
automatically using maturin. Provides clear error messages if build fails.
"""

import sys
import subprocess
import os
from pathlib import Path


def is_frozen() -> bool:
    """Check if running as a PyInstaller frozen executable."""
    return getattr(sys, 'frozen', False)


def is_rust_core_importable() -> bool:
    """Check if anonymizer_core can be imported."""
    try:
        import anonymizer_core
        return True
    except ImportError:
        return False


def get_rust_env() -> tuple[dict, Path] | None:
    """Get environment with Rust toolchain in PATH.

    Returns (env_dict, cargo_bin_path) or None if Rust not found.
    """
    cargo_bin_paths = [
        Path.home() / ".cargo" / "bin",
        Path("C:/Users") / os.environ.get("USERNAME", "") / ".cargo" / "bin",
    ]

    env = os.environ.copy()

    for cargo_bin in cargo_bin_paths:
        rustc_path = cargo_bin / ("rustc.exe" if sys.platform == "win32" else "rustc")
        if rustc_path.exists():
            env["PATH"] = str(cargo_bin) + os.pathsep + env.get("PATH", "")
            return env, cargo_bin

    # Check if Rust is already in PATH
    try:
        result = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            return env, None
    except FileNotFoundError:
        pass

    return None


def find_rust_core_dir() -> Path | None:
    """Find the rust_core directory relative to this script."""
    candidate = Path(__file__).parent / "rust_core"
    if (candidate / "pyproject.toml").exists():
        return candidate
    return None


def auto_build_rust_core(progress_callback=None) -> bool:
    """Attempt to build the Rust extension automatically.

    Args:
        progress_callback: Optional callable(str) for status messages.

    Returns:
        True if build succeeded and the module is now importable.
    """
    def notify(msg: str):
        if progress_callback:
            progress_callback(msg)
        else:
            print(msg)

    rust_dir = find_rust_core_dir()
    if rust_dir is None:
        notify("Error: rust_core/ directory not found. Cannot auto-build.")
        return False

    # Check for maturin
    try:
        result = subprocess.run(
            [sys.executable, "-m", "maturin", "--version"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            notify("maturin is not installed. Install with: pip install maturin")
            return False
    except FileNotFoundError:
        notify("maturin is not installed. Install with: pip install maturin")
        return False

    # Check for Rust toolchain
    rust_result = get_rust_env()
    if rust_result is None:
        notify(
            "Rust toolchain not found.\n"
            "Install from: https://rustup.rs/\n"
            "Then run this script again."
        )
        return False

    rust_env, _ = rust_result

    notify("Building Rust extension (first run only, takes 1-3 minutes)...")

    result = subprocess.run(
        [sys.executable, "-m", "maturin", "develop", "--release"],
        cwd=str(rust_dir),
        capture_output=True,
        text=True,
        env=rust_env,
    )

    if result.returncode != 0:
        notify(f"Rust build failed:\n{result.stderr}")
        return False

    # Verify it's now importable
    if is_rust_core_importable():
        notify("Rust extension built successfully!")
        return True
    else:
        notify("Build appeared to succeed but module still not importable.")
        return False


def ensure_rust_core(progress_callback=None):
    """Ensure the Rust core is available. Auto-builds if needed.

    Call this BEFORE importing anonymizer or pattern_matcher for the first time.
    Raises ImportError with instructions if it cannot be resolved.
    """
    if is_frozen():
        return

    if is_rust_core_importable():
        return

    success = auto_build_rust_core(progress_callback=progress_callback)

    if success:
        # Reload the Rust core in pattern_matcher if it was already imported
        if 'pattern_matcher' in sys.modules:
            from pattern_matcher import reload_rust_core
            reload_rust_core()
        return

    raise ImportError(
        "Rust anonymization core (anonymizer_core) is required but could not be built automatically.\n"
        "\n"
        "To fix this manually:\n"
        "  1. Install Rust from: https://rustup.rs/\n"
        "  2. Install maturin: pip install maturin\n"
        "  3. Build the extension: cd rust_core && maturin develop --release\n"
        "  4. Run this script again."
    )
