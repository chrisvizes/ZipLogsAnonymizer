#!/usr/bin/env python3
"""
ZipLogsAnonymizer - Anonymize sensitive data in log archives for safe sharing with LLMs.

Usage: python anonymizer.py <path_to_zipfile>

Optised for large zip files (up to 2GB) with:
- Streaming processing to minimize memory usage
- Parallel anonymization with immediate disk writes
- Outputs to an unzipped directory (preserving original structure)
- 5x faster pattern matching via pre-filtering and line-by-line processing
- ThreadPoolExecutor for large files (regex releases GIL)
- Optimized I/O with larger buffers
"""

import argparse
import sys
import time
import zipfile
from collections import defaultdict
from concurrent.futures import (
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    as_completed,
    Future,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable
import multiprocessing
import threading


class CancelledException(Exception):
    """Raised when processing is cancelled by user."""

    pass


# Import pattern matching
from pattern_matcher import PatternMatcher, anonymize_content as pattern_anonymize


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
MAX_CONCURRENT_FUTURES = 16  # Max small files in-flight at once
LARGE_FILE_THRESHOLD = (
    5 * 1024 * 1024
)  # 5MB - larger files use thread pool instead of serial

# Memory safety settings
MEMORY_SAFETY_FACTOR = 2.0  # Assume each file needs ~2x its size in memory (read + output buffer)
MIN_FREE_MEMORY_MB = 400  # Always keep at least 400MB free

# Parallel processing settings
MIN_PARALLEL_SIZE_MB = 10  # Only parallelize files larger than this
PARALLEL_CHUNK_LINES = 50000  # Lines per chunk for parallel processing


def _process_lines_chunk(args: tuple) -> tuple[list[str], dict[str, int]]:
    """
    Process a chunk of lines in a worker process.

    Must be at module level to be picklable for ProcessPoolExecutor.

    Args:
        args: Tuple of (lines_chunk, present_keywords)

    Returns:
        Tuple of (processed_lines, replacement_counts)
    """
    lines_chunk, present_keywords = args

    # Import inside worker to get fresh matcher per process
    from pattern_matcher import PatternMatcher, FastAnonymizer

    matcher = PatternMatcher()
    anonymizer = FastAnonymizer(matcher)

    keyword_to_patterns = matcher._keyword_to_patterns

    # Build applicable pattern IDs from present keywords
    present_pattern_ids = set()
    for kw in present_keywords:
        for pattern in keyword_to_patterns.get(kw, []):
            if not pattern.multiline:
                present_pattern_ids.add(id(pattern))

    # Process lines in-place
    for i, line in enumerate(lines_chunk):
        if not line:
            continue

        line_lower = line.lower()

        # Check for keywords
        has_keyword = False
        for kw in present_keywords:
            if kw in line_lower:
                has_keyword = True
                break

        if not has_keyword:
            continue

        # Collect applicable patterns
        seen_patterns = set()
        applicable = []
        for kw in present_keywords:
            if kw in line_lower:
                for pattern in keyword_to_patterns.get(kw, []):
                    if id(pattern) in present_pattern_ids and id(pattern) not in seen_patterns:
                        seen_patterns.add(id(pattern))
                        applicable.append(pattern)

        if not applicable:
            continue

        modified = line
        for config in applicable:
            modified = anonymizer.apply_pattern(config, modified)

        if modified != line:
            lines_chunk[i] = modified

    return lines_chunk, dict(anonymizer.counts)


def get_available_memory_mb() -> float:
    """Get available system memory in MB. Cross-platform."""
    try:
        import psutil
        return psutil.virtual_memory().available / (1024 * 1024)
    except ImportError:
        # psutil not installed - try platform-specific methods
        pass

    # Windows fallback
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulonglong = ctypes.c_ulonglong

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", c_ulonglong),
                    ("ullAvailPhys", c_ulonglong),
                    ("ullTotalPageFile", c_ulonglong),
                    ("ullAvailPageFile", c_ulonglong),
                    ("ullTotalVirtual", c_ulonglong),
                    ("ullAvailVirtual", c_ulonglong),
                    ("ullAvailExtendedVirtual", c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return stat.ullAvailPhys / (1024 * 1024)
        except Exception:
            pass

    # Linux/Mac fallback
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemAvailable:'):
                    return int(line.split()[1]) / 1024  # Convert KB to MB
    except Exception:
        pass

    # Ultimate fallback: assume 4GB available
    return 4096.0


def calculate_max_concurrent_files(file_sizes_bytes: list[int]) -> int:
    """
    Calculate how many files can be safely processed concurrently based on memory.

    Args:
        file_sizes_bytes: List of file sizes in bytes

    Returns:
        Maximum number of files to process concurrently (at least 1)
    """
    if not file_sizes_bytes:
        return 1

    available_mb = get_available_memory_mb()
    usable_mb = max(0, available_mb - MIN_FREE_MEMORY_MB)

    if usable_mb <= 0:
        print(f"  WARNING: Low memory ({available_mb:.0f} MB available). Processing files one at a time.")
        return 1

    # Sort files by size descending to consider worst case
    sorted_sizes = sorted(file_sizes_bytes, reverse=True)

    # Calculate how many of the largest files we can fit
    total_required = 0
    max_concurrent = 0
    for size_bytes in sorted_sizes:
        size_mb = size_bytes / (1024 * 1024)
        memory_needed = size_mb * MEMORY_SAFETY_FACTOR
        if total_required + memory_needed <= usable_mb:
            total_required += memory_needed
            max_concurrent += 1
        else:
            break

    # Always allow at least 1
    max_concurrent = max(1, max_concurrent)

    print(f"  Memory available: {available_mb:.0f} MB | Usable: {usable_mb:.0f} MB | Max concurrent: {max_concurrent}")

    return max_concurrent


def format_time(seconds: float) -> str:
    """Format seconds into human-readable time string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.0f}s"


class ProgressBar:
    """Simple text-based progress bar."""

    def __init__(
        self, total: int, description: str = "", width: int = 40, show_eta: bool = True
    ):
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
            time_str = f" ETA: {format_time(eta)}"
        else:
            time_str = f" {format_time(elapsed)}"

        line = f"\r{self.description}: [{bar}] {pct:3d}% ({self.current}/{self.total}){time_str}"
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        """Complete the progress bar."""
        self.current = self.total
        self._render()
        print()  # New line


class LargeFileProgress:
    """Progress display for processing large files with throughput tracking and ETA."""

    def __init__(self, total_files: int, total_size_mb: float, max_concurrent: int = 1):
        self.total_files = total_files
        self.total_size_mb = total_size_mb
        self.completed = 0
        self.completed_mb = 0.0
        self.start_time = time.time()
        self.max_concurrent = max_concurrent
        self._lock = threading.Lock()
        # Track per-file timing for throughput calculation
        self._file_starts: dict[str, tuple[float, float]] = {}  # filename -> (start_time, size_mb)
        self._throughputs: list[float] = []  # MB/s for each completed file
        self._render_header()

    def _render_header(self):
        """Print header for large file processing."""
        if self.max_concurrent > 1:
            mode = f"(max {self.max_concurrent} files concurrent)"
        else:
            mode = "(one at a time, parallel chunks)"
        print(f"\nProcessing {self.total_files} large file(s) ({self.total_size_mb:.1f} MB total) {mode}")
        print("-" * 75)

    def get_average_throughput(self) -> float:
        """Get average throughput in MB/s across all completed files."""
        with self._lock:
            if not self._throughputs:
                return 0.0
            return sum(self._throughputs) / len(self._throughputs)

    def get_eta_seconds(self) -> Optional[float]:
        """Get estimated time remaining in seconds."""
        avg_throughput = self.get_average_throughput()
        if avg_throughput <= 0:
            return None
        remaining_mb = self.total_size_mb - self.completed_mb
        return remaining_mb / avg_throughput

    def start_file(self, filename: str, size_bytes: int):
        """Mark start of processing a new file (thread-safe)."""
        display_name = Path(filename).name
        if len(display_name) > 40:
            display_name = display_name[:37] + "..."
        size_mb = size_bytes / 1024 / 1024
        with self._lock:
            self._file_starts[filename] = (time.time(), size_mb)
            sys.stdout.write(f"  START: {display_name} ({size_mb:.1f} MB)\n")
            sys.stdout.flush()

    def finish_file(self, filename: str, replacements: int):
        """Mark completion of current file with throughput stats (thread-safe)."""
        display_name = Path(filename).name
        if len(display_name) > 28:
            display_name = display_name[:25] + "..."

        with self._lock:
            self.completed += 1

            # Calculate throughput for this file
            file_throughput = 0.0
            file_size_mb = 0.0
            if filename in self._file_starts:
                start_time, file_size_mb = self._file_starts[filename]
                elapsed = time.time() - start_time
                if elapsed > 0:
                    file_throughput = file_size_mb / elapsed
                    self._throughputs.append(file_throughput)
                self.completed_mb += file_size_mb
                del self._file_starts[filename]

            # Calculate average and ETA
            avg_throughput = sum(self._throughputs) / len(self._throughputs) if self._throughputs else 0
            remaining_mb = self.total_size_mb - self.completed_mb
            eta_str = ""
            if avg_throughput > 0 and remaining_mb > 0:
                eta_seconds = remaining_mb / avg_throughput
                eta_str = f" | ETA: {format_time(eta_seconds)}"

            sys.stdout.write(
                f"  DONE [{self.completed}/{self.total_files}]: {display_name} "
                f"({file_size_mb:.1f} MB @ {file_throughput:.2f} MB/s, {replacements} repl)"
                f"{eta_str} | Avg: {avg_throughput:.2f} MB/s\n"
            )
            sys.stdout.flush()

    def finish(self) -> dict:
        """Complete large file processing and return stats."""
        elapsed = time.time() - self.start_time
        avg_throughput = self.get_average_throughput()
        print("-" * 75)
        print(f"Large files completed in {format_time(elapsed)}")
        if avg_throughput > 0:
            print(f"Average throughput: {avg_throughput:.2f} MB/s | Total: {self.completed_mb:.1f} MB")
        print()
        return {
            "elapsed_seconds": elapsed,
            "total_mb": self.completed_mb,
            "avg_throughput_mb_s": avg_throughput,
            "throughputs": list(self._throughputs),
        }


@dataclass
class AnonymizationResult:
    """Result from anonymizing a single file."""

    filename: str
    content: bytes
    replacements: dict[str, int]  # category -> count (not full list, to save memory)
    error: Optional[str] = None


# Global pattern matcher (compiled once per process)
_matcher: Optional[PatternMatcher] = None


def get_matcher() -> PatternMatcher:
    global _matcher
    if _matcher is None:
        _matcher = PatternMatcher()
    return _matcher


def is_likely_binary(data: bytes, sample_size: int = 8192) -> bool:
    """Quick check if data is likely binary."""
    sample = data[:sample_size]
    if b"\x00" in sample:
        return True
    non_text = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
    return non_text / len(sample) > 0.1 if sample else False


def anonymize_content(
    content: str, matcher: PatternMatcher
) -> tuple[str, dict[str, int]]:
    """Anonymize content using pattern matching.

    Returns (anonymized_content, category -> count).
    """
    return pattern_anonymize(content, matcher)


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


def process_large_file_streaming(
    data: bytes,
    output_path: Path,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> tuple[dict[str, int], Optional[str]]:
    """
    Process a large file using streaming to reduce memory pressure.
    Writes output directly to disk in chunks.

    When Rust core is available, uses high-performance Rust processing.
    Falls back to Python chunked processing when Rust is not available.

    Args:
        data: Raw file content bytes
        output_path: Where to write the processed output
        cancel_check: Optional callback that returns True if processing should stop

    Returns (counts_dict, error_string_or_none)
    """
    from pattern_matcher import FastAnonymizer, RUST_CORE_AVAILABLE

    if is_likely_binary(data):
        output_path.write_bytes(data)
        return {}, None

    # Detect encoding from first chunk (avoid loading entire file)
    encoding_to_use = None
    test_chunk = data[:min(len(data), 10000)]
    for encoding in ["utf-8", "utf-16", "latin-1", "cp1252"]:
        try:
            test_chunk.decode(encoding)
            encoding_to_use = encoding
            break
        except (UnicodeDecodeError, LookupError):
            continue

    if encoding_to_use is None:
        output_path.write_bytes(data)
        return {}, None

    try:
        # When Rust core is available, use memory-efficient byte-chunked processing
        # This processes bytes directly without loading the entire file as a string
        if RUST_CORE_AVAILABLE:
            if cancel_check and cancel_check():
                raise CancelledException("Processing cancelled by user")

            # Memory-efficient chunked processing with Rust
            # Process in ~100MB chunks, decoding only each chunk
            CHUNK_SIZE_BYTES = 100 * 1024 * 1024  # 100MB chunks

            data_size = len(data)
            matcher = get_matcher()
            anonymizer = FastAnonymizer(matcher)
            all_counts: dict[str, int] = defaultdict(int)

            # For small files (< 200MB), process in one shot for simplicity
            if data_size < CHUNK_SIZE_BYTES * 2:
                content = data.decode(encoding_to_use)
                del data  # Free bytes immediately
                result, counts = anonymizer.process_content(content)
                del content  # Free input before writing output
                output_path.write_text(result, encoding="utf-8")
                return dict(counts), None

            # For large files, process bytes in chunks
            # This keeps memory usage bounded: ~2x chunk size at any time
            first_chunk = True
            position = 0
            leftover_bytes = b""  # Partial line from previous chunk

            with open(output_path, 'w', encoding='utf-8', buffering=4*1024*1024) as f:
                while position < data_size:
                    if cancel_check and cancel_check():
                        raise CancelledException("Processing cancelled by user")

                    # Read chunk of bytes
                    end_pos = min(position + CHUNK_SIZE_BYTES, data_size)
                    chunk_bytes = leftover_bytes + data[position:end_pos]
                    position = end_pos

                    # Find last newline to avoid splitting mid-line
                    if position < data_size:
                        last_newline = chunk_bytes.rfind(b'\n')
                        if last_newline != -1:
                            leftover_bytes = chunk_bytes[last_newline + 1:]
                            chunk_bytes = chunk_bytes[:last_newline + 1]
                        else:
                            # No newline found - keep accumulating (rare for text files)
                            leftover_bytes = chunk_bytes
                            continue
                    else:
                        leftover_bytes = b""

                    # Decode only this chunk
                    try:
                        chunk_content = chunk_bytes.decode(encoding_to_use)
                    except UnicodeDecodeError:
                        # Fallback: try latin-1 which accepts any byte
                        chunk_content = chunk_bytes.decode('latin-1')
                    del chunk_bytes  # Free bytes

                    # Process with Rust (preserve unique counters across chunks)
                    chunk_result, chunk_counts = anonymizer.process_content(
                        chunk_content, full_reset=first_chunk
                    )
                    first_chunk = False
                    del chunk_content  # Free input chunk

                    # Accumulate counts
                    for cat, count in chunk_counts.items():
                        all_counts[cat] += count

                    # Write chunk result immediately and free memory
                    f.write(chunk_result)
                    del chunk_result  # Free output chunk

                # Process any remaining leftover
                if leftover_bytes:
                    try:
                        chunk_content = leftover_bytes.decode(encoding_to_use)
                    except UnicodeDecodeError:
                        chunk_content = leftover_bytes.decode('latin-1')

                    chunk_result, chunk_counts = anonymizer.process_content(
                        chunk_content, full_reset=False
                    )
                    for cat, count in chunk_counts.items():
                        all_counts[cat] += count
                    f.write(chunk_result)

            # Free the original data now that we're done
            del data
            return dict(all_counts), None

        # Fall back to Python streaming for memory efficiency when Rust is not available
        # Decode full content for Python path (needed for line-by-line processing)
        content = data.decode(encoding_to_use)
        del data
        matcher = get_matcher()
        # Create a fresh anonymizer for this file
        anonymizer = FastAnonymizer(matcher)

        # Pre-fetch for hot loop
        multiline_patterns = matcher._multiline_patterns
        all_keywords = matcher._all_keywords_lower
        keyword_to_patterns = matcher._keyword_to_patterns

        # OPTIMIZATION: Scan for present keywords, then discard lowercase content
        # This avoids keeping 2x memory for large files
        content_lower_temp = content.lower()
        present_keywords = [kw for kw in all_keywords if kw in content_lower_temp]

        # Fast path: no keywords present anywhere in file
        if not present_keywords:
            del content_lower_temp  # Free memory immediately
            output_path.write_text(content, encoding="utf-8")
            return {}, None

        # First pass: handle multiline patterns on full content
        for config in multiline_patterns:
            if any(kw in content_lower_temp for kw in config.required_keywords):
                content = anonymizer.apply_pattern(config, content)
                content_lower_temp = content.lower()  # Update after modification

        # Build set of applicable pattern IDs based on present keywords only
        present_pattern_ids = set()
        for kw in present_keywords:
            for pattern in keyword_to_patterns.get(kw, []):
                if not pattern.multiline:
                    present_pattern_ids.add(id(pattern))

        # Free the large lowercase string - we'll lowercase per-chunk instead
        del content_lower_temp

        # Fast path: no single-line patterns apply
        if not present_pattern_ids:
            output_path.write_text(content, encoding="utf-8")
            return dict(anonymizer.counts), None

        # Split content into lines
        lines = content.split("\n")
        total_lines = len(lines)

        # Free original content string - we have it in lines now
        del content

        # Determine if parallel processing is beneficial
        # Only parallelize if file is large enough (>10MB of lines)
        content_size_mb = sum(len(line) for line in lines) / (1024 * 1024)
        num_workers = min(4, multiprocessing.cpu_count())
        use_parallel = content_size_mb >= MIN_PARALLEL_SIZE_MB and num_workers >= 2

        if use_parallel:
            # PARALLEL PROCESSING: Split into chunks and process in parallel
            chunk_size = max(PARALLEL_CHUNK_LINES, total_lines // num_workers)
            chunks = []
            for i in range(0, total_lines, chunk_size):
                chunk = lines[i:i + chunk_size]
                chunks.append((chunk, present_keywords))

            # Process chunks in parallel
            all_counts: dict[str, int] = defaultdict(int)
            processed_chunks = []

            # Check for cancellation before starting parallel work
            if cancel_check and cancel_check():
                raise CancelledException("Processing cancelled by user")

            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                results = list(executor.map(_process_lines_chunk, chunks))

            # Check for cancellation after parallel work completes
            if cancel_check and cancel_check():
                raise CancelledException("Processing cancelled by user")

            for processed_lines, chunk_counts in results:
                processed_chunks.append(processed_lines)
                for cat, count in chunk_counts.items():
                    all_counts[cat] += count

            # Write all processed chunks to file
            with open(output_path, "w", encoding="utf-8", buffering=4 * 1024 * 1024) as f:
                first = True
                for chunk in processed_chunks:
                    if not first:
                        f.write("\n")
                    f.write("\n".join(chunk))
                    first = False

            return dict(all_counts), None

        else:
            # SEQUENTIAL PROCESSING: For smaller files, process in-place
            CHUNK_LINES = 25000

            with open(
                output_path, "w", encoding="utf-8", buffering=4 * 1024 * 1024
            ) as f:
                chunk_start = 0
                first_chunk = True
                while chunk_start < total_lines:
                    # Check for cancellation between chunks
                    if cancel_check and cancel_check():
                        raise CancelledException("Processing cancelled by user")

                    chunk_end = min(chunk_start + CHUNK_LINES, total_lines)
                    chunk_lines = lines[chunk_start:chunk_end]

                    # Process in-place using only present keywords
                    for i, line in enumerate(chunk_lines):
                        if not line:
                            continue

                        line_lower = line.lower()

                        has_keyword = False
                        for kw in present_keywords:
                            if kw in line_lower:
                                has_keyword = True
                                break

                        if not has_keyword:
                            continue

                        seen_patterns = set()
                        applicable = []
                        for kw in present_keywords:
                            if kw in line_lower:
                                for pattern in keyword_to_patterns.get(kw, []):
                                    if (
                                        id(pattern) in present_pattern_ids
                                        and id(pattern) not in seen_patterns
                                    ):
                                        seen_patterns.add(id(pattern))
                                        applicable.append(pattern)

                        if not applicable:
                            continue

                        modified = line
                        for config in applicable:
                            modified = anonymizer.apply_pattern(config, modified)

                        if modified != line:
                            chunk_lines[i] = modified

                    if not first_chunk:
                        f.write("\n")
                    f.write("\n".join(chunk_lines))
                    first_chunk = False

                    chunk_start = chunk_end

            return dict(anonymizer.counts), None

    except Exception as e:
        # On error, write original data
        output_path.write_bytes(data)
        return {}, str(e)


def process_zip(
    zip_path: str,
    max_workers: Optional[int] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    create_zip: bool = True,
    keep_uncompressed: bool = True,
) -> bool:
    """
    Main processing function with streaming writes for memory efficiency.

    Key optimizations:
    - Processes files in batches to limit memory usage
    - Writes results immediately to disk (doesn't store all in memory)
    - Shows progress bar for all phases

    Args:
        zip_path: Path to the zip file to process
        max_workers: Number of parallel workers (default: CPU count, max 8)
        cancel_check: Optional callback that returns True if processing should be cancelled
        create_zip: Create a zip file from the output (default: True, for LogShark compatibility)
        keep_uncompressed: Keep the uncompressed directory (default: True)
    """
    import shutil

    def check_cancelled():
        """Check if cancellation was requested and raise if so."""
        if cancel_check and cancel_check():
            raise CancelledException("Processing cancelled by user")

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
            # Silent copy - no progress bar needed for binary files
            if binary_entries:
                check_cancelled()
                for entry in binary_entries:
                    check_cancelled()
                    data = src_zip.read(entry.filename)
                    out_path = output_dir / entry.filename
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_bytes(data)
                print(f"Copied {len(binary_entries)} binary files")

            # Phase 2: Process text files with memory-efficient streaming
            if text_entries:
                # Separate large files (memory-aware threading) from small files (multiprocessing)
                large_files = [
                    e for e in text_entries if e.file_size >= LARGE_FILE_THRESHOLD
                ]
                small_files = [
                    e for e in text_entries if e.file_size < LARGE_FILE_THRESHOLD
                ]

                # Process large files with memory-aware concurrency
                # (Threading works well here because regex releases the GIL)
                if large_files:
                    check_cancelled()
                    large_total_mb = sum(e.file_size for e in large_files) / 1024 / 1024

                    # Calculate safe concurrency based on available memory
                    file_sizes = [e.file_size for e in large_files]
                    max_concurrent = calculate_max_concurrent_files(file_sizes)

                    large_progress = LargeFileProgress(
                        len(large_files), large_total_mb, max_concurrent=max_concurrent
                    )

                    # Thread-safe stats collection
                    stats_lock = threading.Lock()

                    # Threshold for using streaming (20MB+)
                    STREAMING_THRESHOLD = 20 * 1024 * 1024

                    def process_large_file(entry):
                        """Process a single large file (runs in thread)."""
                        large_progress.start_file(entry.filename, entry.file_size)
                        data = src_zip.read(entry.filename)

                        out_path = output_dir / entry.filename
                        out_path.parent.mkdir(parents=True, exist_ok=True)

                        # Use streaming for very large files to reduce memory pressure
                        if entry.file_size >= STREAMING_THRESHOLD:
                            counts, error = process_large_file_streaming(
                                data, out_path, cancel_check=cancel_check
                            )
                            file_replacements = sum(counts.values())
                            with stats_lock:
                                for cat, count in counts.items():
                                    total_stats[cat] += count
                                if error:
                                    errors.append(f"{entry.filename}: {error}")
                        else:
                            result = process_single_file((entry.filename, data))
                            out_path.write_bytes(result.content)
                            file_replacements = sum(result.replacements.values())
                            with stats_lock:
                                for cat, count in result.replacements.items():
                                    total_stats[cat] += count
                                if result.error:
                                    errors.append(f"{result.filename}: {result.error}")
                            del result

                        large_progress.finish_file(entry.filename, file_replacements)

                        # Free memory
                        del data
                        return entry.filename

                    if max_concurrent > 1 and len(large_files) >= 2:
                        # Use thread pool with memory-safe concurrency
                        num_threads = min(max_concurrent, len(large_files))
                        with ThreadPoolExecutor(max_workers=num_threads) as executor:
                            futures = {
                                executor.submit(process_large_file, entry): entry
                                for entry in large_files
                            }
                            for future in as_completed(futures):
                                check_cancelled()
                                try:
                                    future.result()
                                except Exception as e:
                                    entry = futures[future]
                                    errors.append(f"{entry.filename}: {e}")
                    else:
                        # Process one file at a time (memory constrained or single file)
                        # Note: each file's content is still processed with parallel chunks
                        for entry in large_files:
                            check_cancelled()
                            process_large_file(entry)

                    large_progress.finish()

                # Process small files in parallel with limited concurrency
                if small_files:
                    check_cancelled()
                    # Don't show ETA for small files - it's misleading early on
                    progress = ProgressBar(
                        len(small_files), "Small files  ", show_eta=False
                    )

                    with ProcessPoolExecutor(max_workers=max_workers) as executor:
                        pending_futures: dict[Future, any] = {}
                        file_iter = iter(small_files)
                        done = False

                        try:
                            while not done or pending_futures:
                                # Check for cancellation before submitting more work
                                check_cancelled()

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

                                # Wait for at least one to complete (with timeout for responsiveness)
                                for completed in as_completed(
                                    pending_futures, timeout=0.5
                                ):
                                    result = completed.result()

                                    # Write result to disk immediately
                                    out_path = output_dir / result.filename
                                    out_path.parent.mkdir(parents=True, exist_ok=True)
                                    out_path.write_bytes(result.content)

                                    # Track stats
                                    for cat, count in result.replacements.items():
                                        total_stats[cat] += count
                                    if result.error:
                                        errors.append(
                                            f"{result.filename}: {result.error}"
                                        )

                                    del pending_futures[completed]
                                    progress.update()
                                    break  # Process one at a time to check cancellation

                        except TimeoutError:
                            # Timeout is expected - just continue loop to check cancellation
                            pass

                    progress.finish()

        # Calculate timing
        elapsed = time.time() - start_time

        # Create zip file if requested (for LogShark compatibility)
        output_zip_path = None
        if create_zip:
            output_zip_path = zip_path.parent / (zip_path.stem + "_anonymized.zip")
            print(f"\nCreating output zip file...")
            with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in output_dir.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(output_dir)
                        zf.write(file_path, arcname)
            zip_size_mb = output_zip_path.stat().st_size / 1024 / 1024
            print(f"Created: {output_zip_path.name} ({zip_size_mb:.1f} MB)")

        # Remove uncompressed directory if not keeping it
        if create_zip and not keep_uncompressed:
            shutil.rmtree(output_dir)
            output_dir = None

        # Print results
        print("\n" + "=" * 60)
        print("ANONYMIZATION COMPLETE")
        print("=" * 60)
        if output_zip_path:
            print(f"\nOutput zip: {output_zip_path}")
        if output_dir and output_dir.exists():
            print(f"Output directory: {output_dir}")
        print(f"Original zip size: {zip_path.stat().st_size / 1024 / 1024:.1f} MB")
        print(f"Files processed: {total_files}")
        print(f"Total time: {format_time(elapsed)}")

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

    except CancelledException:
        print("\n\nProcessing cancelled by user.")
        # Clean up partial output
        if output_dir.exists():
            print(f"Cleaning up partial output: {output_dir}")
            shutil.rmtree(output_dir)
        print("Cancelled successfully - no output created.")
        return False

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
    parser.add_argument(
        "--no-zip",
        action="store_true",
        help="Don't create output zip file (only keep uncompressed directory)",
    )
    parser.add_argument(
        "--no-uncompressed",
        action="store_true",
        help="Don't keep uncompressed directory (only create zip file)",
    )

    args = parser.parse_args()

    success = process_zip(
        args.zipfile,
        args.workers,
        create_zip=not args.no_zip,
        keep_uncompressed=not args.no_uncompressed,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    multiprocessing.freeze_support()  # Required for Windows
    main()
