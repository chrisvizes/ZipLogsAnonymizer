#!/usr/bin/env python3
"""
ZipLogsAnonymizer - Anonymize sensitive data in log archives for safe sharing with LLMs.

Usage: python anonymizer.py <path_to_zipfile>

Optimized for large zip files (up to 2GB) with:
- Streaming processing to minimize memory usage
- Parallel anonymization with immediate disk writes
- Outputs to an unzipped directory (preserving original structure)
- 5x faster pattern matching via pre-filtering and line-by-line processing
"""

import argparse
import sys
import time
import zipfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import multiprocessing

# Import optimized pattern matching
from pattern_matcher_optimized import (
    OptimizedPatternMatcher,
    anonymize_content_optimized,
)


# File extensions to process as text
TEXT_EXTENSIONS = {
    ".log",
    ".txt",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".properties",
    ".conf",
    ".config",
    ".html",
    ".htm",
}

# Concurrency limits for memory management
MAX_CONCURRENT_FUTURES = 8  # Max files in-flight at once (limits memory)
LARGE_FILE_THRESHOLD = (
    5 * 1024 * 1024
)  # 5MB - larger files processed serially in main process


class ProgressBar:
    """Simple text-based progress bar."""

    def __init__(self, total: int, description: str = "", width: int = 40, show_eta: bool = True):
        self.total = total
        self.current = 0
        self.description = description
        self.width = width
        self.start_time = time.time()
        self.show_eta = show_eta
        # Render immediately so progress bar shows right away
        self._render()

    def update(self, n: int = 1):
        """Update progress by n items."""
        self.current += n
        self._render()

    def set(self, value: int):
        """Set progress to specific value."""
        self.current = value
        self._render()

    def _render(self):
        """Render the progress bar."""
        if self.total == 0:
            pct = 100
        else:
            pct = min(100, self.current * 100 // self.total)

        filled = self.width * self.current // max(self.total, 1)
        bar = "=" * filled + "-" * (self.width - filled)

        elapsed = time.time() - self.start_time
        if self.show_eta and self.current > 0 and self.current < self.total:
            eta = elapsed * (self.total - self.current) / self.current
            time_str = f" ETA: {eta:.0f}s"
        else:
            time_str = f" {elapsed:.1f}s"

        line = f"\r{self.description}: [{bar}] {pct:3d}% ({self.current}/{self.total}){time_str}"
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        """Complete the progress bar."""
        self.current = self.total
        self._render()
        print()  # New line


class LargeFileProgress:
    """Progress display for processing large files one at a time."""

    def __init__(self, total_files: int, total_size_mb: float):
        self.total_files = total_files
        self.total_size_mb = total_size_mb
        self.current_file = 0
        self.start_time = time.time()
        self.current_file_name = ""
        self.current_file_size_mb = 0
        self._render_header()

    def _render_header(self):
        """Print header for large file processing."""
        print(f"\nProcessing {self.total_files} large file(s) ({self.total_size_mb:.1f} MB total)")
        print("Large files are processed serially - this may take several minutes...")
        print("-" * 60)

    def start_file(self, filename: str, size_bytes: int):
        """Mark start of processing a new file."""
        self.current_file += 1
        self.current_file_name = Path(filename).name
        self.current_file_size_mb = size_bytes / 1024 / 1024
        # Truncate long filenames
        display_name = self.current_file_name[:40] + "..." if len(self.current_file_name) > 43 else self.current_file_name
        sys.stdout.write(f"\r[{self.current_file}/{self.total_files}] {display_name} ({self.current_file_size_mb:.1f} MB)...")
        sys.stdout.flush()

    def finish_file(self, replacements: int):
        """Mark completion of current file."""
        sys.stdout.write(f" done ({replacements} replacements)\n")
        sys.stdout.flush()

    def finish(self):
        """Complete large file processing."""
        elapsed = time.time() - self.start_time
        print(f"-" * 60)
        print(f"Large files completed in {elapsed:.1f}s\n")


@dataclass
class AnonymizationResult:
    """Result from anonymizing a single file."""

    filename: str
    content: bytes
    replacements: dict[str, int]  # category -> count (not full list, to save memory)
    error: Optional[str] = None


# Alias for backwards compatibility with tests
PatternMatcher = OptimizedPatternMatcher


# Global pattern matcher (compiled once per process)
_matcher: Optional[OptimizedPatternMatcher] = None


def get_matcher() -> OptimizedPatternMatcher:
    global _matcher
    if _matcher is None:
        _matcher = OptimizedPatternMatcher()
    return _matcher


def is_likely_binary(data: bytes, sample_size: int = 8192) -> bool:
    """Quick check if data is likely binary."""
    sample = data[:sample_size]
    if b"\x00" in sample:
        return True
    non_text = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
    return non_text / len(sample) > 0.1 if sample else False


def anonymize_content(
    content: str, matcher: OptimizedPatternMatcher
) -> tuple[str, dict[str, int]]:
    """Anonymize content using optimized pattern matching.

    Returns (anonymized_content, category -> count).
    """
    return anonymize_content_optimized(content, matcher)


def process_single_file(args: tuple[str, bytes]) -> AnonymizationResult:
    """Process a single file's content."""
    filename, data = args

    if is_likely_binary(data):
        return AnonymizationResult(filename, data, {})

    content = None
    for encoding in ["utf-8", "utf-16", "latin-1", "cp1252"]:
        try:
            content = data.decode(encoding)
            break
        except (UnicodeDecodeError, LookupError):
            continue

    if content is None:
        return AnonymizationResult(filename, data, {})

    try:
        matcher = get_matcher()
        anonymized, counts = anonymize_content(content, matcher)
        return AnonymizationResult(filename, anonymized.encode("utf-8"), counts)
    except Exception as e:
        return AnonymizationResult(filename, data, {}, error=str(e))


def process_zip(zip_path: str, max_workers: Optional[int] = None) -> bool:
    """
    Main processing function with streaming writes for memory efficiency.

    Key optimizations:
    - Processes files in batches to limit memory usage
    - Writes results immediately to disk (doesn't store all in memory)
    - Shows progress bar for all phases
    """
    import shutil

    start_time = time.time()
    zip_path = Path(zip_path)

    if not zip_path.exists():
        print(f"Error: File not found: {zip_path}")
        return False

    if not zipfile.is_zipfile(zip_path):
        print(f"Error: Not a valid zip file: {zip_path}")
        return False

    # Output is a directory, not a zip
    output_dir = zip_path.parent / (zip_path.stem + "_anonymized")

    # Clean up any existing output
    if output_dir.exists():
        shutil.rmtree(output_dir)

    if max_workers is None:
        max_workers = min(multiprocessing.cpu_count(), 8)

    print(f"Processing {zip_path.name} with {max_workers} workers...")

    total_stats: dict[str, int] = defaultdict(int)
    errors = []

    try:
        with zipfile.ZipFile(zip_path, "r") as src_zip:
            entries = [e for e in src_zip.infolist() if not e.is_dir()]
            total_files = len(entries)

            # Categorize files
            text_entries = []
            binary_entries = []
            for entry in entries:
                ext = Path(entry.filename).suffix.lower()
                if ext in TEXT_EXTENSIONS:
                    text_entries.append(entry)
                else:
                    binary_entries.append(entry)

            print(
                f"Found {total_files} files: {len(text_entries)} text, {len(binary_entries)} binary/other\n"
            )

            # Create output directory structure
            output_dir.mkdir(parents=True, exist_ok=True)

            # Create all subdirectories first
            for entry in src_zip.infolist():
                if entry.is_dir():
                    (output_dir / entry.filename).mkdir(parents=True, exist_ok=True)

            # Phase 1: Copy binary files directly (no processing needed)
            if binary_entries:
                progress = ProgressBar(len(binary_entries), "Copying binary")
                for entry in binary_entries:
                    data = src_zip.read(entry.filename)
                    out_path = output_dir / entry.filename
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_bytes(data)
                    progress.update()
                progress.finish()

            # Phase 2: Process text files with memory-efficient streaming
            if text_entries:
                # Separate large files (process serially) from small files (process in parallel)
                large_files = [
                    e for e in text_entries if e.file_size >= LARGE_FILE_THRESHOLD
                ]
                small_files = [
                    e for e in text_entries if e.file_size < LARGE_FILE_THRESHOLD
                ]

                # Process large files serially in main process (avoids pickle overhead)
                if large_files:
                    large_total_mb = sum(e.file_size for e in large_files) / 1024 / 1024
                    large_progress = LargeFileProgress(len(large_files), large_total_mb)

                    for entry in large_files:
                        large_progress.start_file(entry.filename, entry.file_size)
                        data = src_zip.read(entry.filename)
                        result = process_single_file((entry.filename, data))

                        # Write immediately
                        out_path = output_dir / result.filename
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        out_path.write_bytes(result.content)

                        # Track stats
                        file_replacements = sum(result.replacements.values())
                        for cat, count in result.replacements.items():
                            total_stats[cat] += count
                        if result.error:
                            errors.append(f"{result.filename}: {result.error}")

                        large_progress.finish_file(file_replacements)

                        # Free memory
                        del data, result

                    large_progress.finish()

                # Process small files in parallel with limited concurrency
                if small_files:
                    # Don't show ETA for small files - it's misleading early on
                    progress = ProgressBar(len(small_files), "Small files  ", show_eta=False)

                    with ProcessPoolExecutor(max_workers=max_workers) as executor:
                        pending_futures = {}
                        file_iter = iter(small_files)
                        done = False

                        while not done or pending_futures:
                            # Submit new work up to concurrency limit
                            while (
                                len(pending_futures) < MAX_CONCURRENT_FUTURES
                                and not done
                            ):
                                try:
                                    entry = next(file_iter)
                                    data = src_zip.read(entry.filename)
                                    future = executor.submit(
                                        process_single_file, (entry.filename, data)
                                    )
                                    pending_futures[future] = entry
                                except StopIteration:
                                    done = True
                                    break

                            if not pending_futures:
                                break

                            # Wait for at least one to complete
                            completed = next(as_completed(pending_futures))
                            result = completed.result()

                            # Write result to disk immediately
                            out_path = output_dir / result.filename
                            out_path.parent.mkdir(parents=True, exist_ok=True)
                            out_path.write_bytes(result.content)

                            # Track stats
                            for cat, count in result.replacements.items():
                                total_stats[cat] += count
                            if result.error:
                                errors.append(f"{result.filename}: {result.error}")

                            del pending_futures[completed]
                            progress.update()

                    progress.finish()

        # Calculate timing
        elapsed = time.time() - start_time
        minutes, seconds = divmod(elapsed, 60)

        # Print results
        print("\n" + "=" * 60)
        print("ANONYMIZATION COMPLETE")
        print("=" * 60)
        print(f"\nOutput directory: {output_dir}")
        print(f"Original zip size: {zip_path.stat().st_size / 1024 / 1024:.1f} MB")
        print(f"Files processed: {total_files}")

        if minutes > 0:
            print(f"Total time: {int(minutes)}m {seconds:.1f}s")
        else:
            print(f"Total time: {seconds:.1f}s")

        if total_stats:
            print(f"\nReplacements made:")
            for cat in sorted(total_stats.keys()):
                print(f"  {cat}: {total_stats[cat]}")
        else:
            print("\nNo sensitive data patterns found.")

        if errors:
            print(f"\nWarnings ({len(errors)}):")
            for err in errors[:5]:
                print(f"  {err}")
            if len(errors) > 5:
                print(f"  ... and {len(errors) - 5} more")

        print("=" * 60)
        return True

    except Exception as e:
        print(f"\nError during processing: {e}")
        import traceback

        traceback.print_exc()
        # Clean up on failure
        if output_dir.exists():
            shutil.rmtree(output_dir)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Anonymize sensitive data in log archives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("zipfile", help="Path to the zip file")
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers (default: CPU count, max 8)",
    )

    args = parser.parse_args()

    success = process_zip(args.zipfile, args.workers)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    multiprocessing.freeze_support()  # Required for Windows
    main()
