#!/usr/bin/env python3
"""
Performance Benchmarking Tool for ZipLogsAnonymizer

Tracks and records:
- Memory usage over time
- CPU usage
- Throughput (MB/s) for each processing phase
- Detailed timing breakdowns
- Pattern matching accuracy verification

Usage:
    python benchmark.py <zipfile> [--output report.json]
    python benchmark.py --synthetic <size_mb>  # Generate synthetic test data

The benchmark runs the anonymizer while collecting detailed metrics,
then outputs a report that can be used to identify bottlenecks and
iterate on optimizations.
"""

import argparse
import json
import multiprocessing
import os
import sys
import tempfile
import threading
import time
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
import io


@dataclass
class MemorySample:
    """A single memory measurement."""
    timestamp: float
    available_mb: float
    used_mb: float
    percent: float


@dataclass
class FileMetrics:
    """Metrics for processing a single file."""
    filename: str
    size_bytes: int
    processing_time_seconds: float
    throughput_mb_s: float
    replacements: int
    is_large_file: bool
    used_streaming: bool = False


@dataclass
class PhaseMetrics:
    """Metrics for a processing phase."""
    name: str
    start_time: float = 0.0
    end_time: float = 0.0
    files_processed: int = 0
    bytes_processed: int = 0
    total_replacements: int = 0

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

    @property
    def throughput_mb_s(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return (self.bytes_processed / (1024 * 1024)) / self.duration_seconds


@dataclass
class BenchmarkReport:
    """Complete benchmark report."""
    zip_path: str
    zip_compressed_size_mb: float  # Compressed zip file size
    zip_uncompressed_size_mb: float  # Total uncompressed size of all files
    total_files: int
    text_files: int
    binary_files: int
    large_files: int
    small_files: int

    # Size breakdowns (all uncompressed)
    text_files_size_mb: float = 0.0
    binary_files_size_mb: float = 0.0
    large_files_size_mb: float = 0.0
    small_files_size_mb: float = 0.0

    # Timing
    total_time_seconds: float = 0.0
    overall_throughput_mb_s: float = 0.0  # Based on uncompressed size

    # Phase breakdown
    phases: dict = field(default_factory=dict)

    # Memory
    peak_memory_mb: float = 0.0
    min_available_memory_mb: float = 0.0
    memory_samples: list = field(default_factory=list)

    # Per-file metrics (sample for large files)
    large_file_metrics: list = field(default_factory=list)

    # Pattern matching
    total_replacements: int = 0
    replacements_by_category: dict = field(default_factory=dict)

    # System info
    cpu_count: int = 0
    platform: str = ""
    initial_available_memory_mb: float = 0.0

    # Accuracy verification (if test data used)
    accuracy_verified: bool = False
    accuracy_errors: list = field(default_factory=list)


class MemoryMonitor:
    """Background thread that samples memory usage."""

    def __init__(self, interval_seconds: float = 0.5):
        self.interval = interval_seconds
        self.samples: list[MemorySample] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.start_time = 0.0

    def start(self):
        """Start monitoring."""
        self.start_time = time.time()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _monitor_loop(self):
        """Sampling loop."""
        while not self._stop_event.is_set():
            sample = self._take_sample()
            if sample:
                self.samples.append(sample)
            self._stop_event.wait(self.interval)

    def _take_sample(self) -> Optional[MemorySample]:
        """Take a single memory sample."""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return MemorySample(
                timestamp=time.time() - self.start_time,
                available_mb=mem.available / (1024 * 1024),
                used_mb=mem.used / (1024 * 1024),
                percent=mem.percent,
            )
        except ImportError:
            # Fallback for Windows without psutil
            try:
                from anonymizer import get_available_memory_mb
                available = get_available_memory_mb()
                return MemorySample(
                    timestamp=time.time() - self.start_time,
                    available_mb=available,
                    used_mb=0,  # Can't measure without psutil
                    percent=0,
                )
            except Exception:
                return None

    def get_peak_used(self) -> float:
        """Get peak memory used in MB."""
        if not self.samples:
            return 0.0
        return max(s.used_mb for s in self.samples)

    def get_min_available(self) -> float:
        """Get minimum available memory in MB."""
        if not self.samples:
            return 0.0
        return min(s.available_mb for s in self.samples)


def create_synthetic_test_zip(size_mb: float, output_path: Path) -> dict:
    """
    Create a synthetic test zip file with known sensitive data patterns.

    Returns dict with expected pattern counts for verification.
    """
    print(f"Creating synthetic test zip ({size_mb:.0f} MB)...")

    expected_counts = defaultdict(int)
    target_bytes = int(size_mb * 1024 * 1024)
    written_bytes = 0

    # Templates with sensitive data
    log_templates = [
        "2024-01-15 10:30:45 INFO  User user=john.smith@company.com logged in from 192.168.1.100\n",
        "2024-01-15 10:30:46 DEBUG Connection string: jdbc:mysql://db.internal:3306/production\n",
        "2024-01-15 10:30:47 WARN  Authentication failed for password=secretpass123\n",
        "2024-01-15 10:30:48 INFO  API call with token=abcdefghij1234567890klmnop\n",
        "2024-01-15 10:30:49 DEBUG Request from server.corp to 10.0.0.50\n",
        "2024-01-15 10:30:50 INFO  Email sent to admin@internal.local\n",
        "2024-01-15 10:30:51 DEBUG MAC address: 00:1A:2B:3C:4D:5E\n",
        "2024-01-15 10:30:52 INFO  Processing workbook=SalesReport for site=Production\n",
        "2024-01-15 10:30:53 DEBUG Normal log line with no sensitive data\n",
        "2024-01-15 10:30:54 INFO  Status check completed successfully\n",
    ]

    # Count expected patterns per template
    pattern_counts_per_template = [
        {"email": 1, "username": 1, "internal_ip": 1},  # template 0
        {"db_connection": 1},  # template 1
        {"password": 1},  # template 2
        {"api_key": 1},  # template 3
        {"hostname": 1, "internal_ip": 1},  # template 4
        {"email": 1, "hostname": 1},  # template 5
        {"mac_address": 1},  # template 6
        {"tableau_entity": 2},  # template 7
        {},  # template 8 - no patterns
        {},  # template 9 - no patterns
    ]

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        file_num = 0

        # Create mix of file sizes
        while written_bytes < target_bytes:
            # Vary file sizes: 70% small (<1MB), 20% medium (1-10MB), 10% large (10-50MB)
            rand_val = (file_num * 7) % 100
            if rand_val < 70:
                file_size_target = 100 * 1024 + (file_num % 900) * 1024  # 100KB - 1MB
            elif rand_val < 90:
                file_size_target = 1 * 1024 * 1024 + (file_num % 9) * 1024 * 1024  # 1-10MB
            else:
                file_size_target = 10 * 1024 * 1024 + (file_num % 4) * 10 * 1024 * 1024  # 10-50MB

            # Don't exceed target
            file_size_target = min(file_size_target, target_bytes - written_bytes)
            if file_size_target <= 0:
                break

            # Generate file content
            content = io.StringIO()
            content_size = 0
            line_num = 0
            file_expected = defaultdict(int)

            while content_size < file_size_target:
                template_idx = line_num % len(log_templates)
                line = log_templates[template_idx]
                content.write(line)
                content_size += len(line)
                line_num += 1

                # Track expected patterns
                for cat, count in pattern_counts_per_template[template_idx].items():
                    file_expected[cat] += count

            # Add to zip
            filename = f"logs/server{file_num % 10}/app_{file_num:04d}.log"
            content_bytes = content.getvalue().encode('utf-8')
            zf.writestr(filename, content_bytes)

            written_bytes += len(content_bytes)
            file_num += 1

            # Accumulate expected counts
            for cat, count in file_expected.items():
                expected_counts[cat] += count

            # Progress
            if file_num % 100 == 0:
                print(f"  Created {file_num} files, {written_bytes / (1024*1024):.1f} MB...")

        # Add some binary files
        for i in range(10):
            binary_data = bytes(range(256)) * 100
            zf.writestr(f"data/binary_{i}.dat", binary_data)

    print(f"  Created {file_num} text files + 10 binary files")
    print(f"  Total size: {output_path.stat().st_size / (1024*1024):.1f} MB")

    return dict(expected_counts)


def run_benchmark(
    zip_path: Path,
    expected_counts: Optional[dict] = None
) -> BenchmarkReport:
    """
    Run the anonymizer with full benchmarking instrumentation.
    """
    from anonymizer import (
        process_zip, TEXT_EXTENSIONS, LARGE_FILE_THRESHOLD,
        get_available_memory_mb
    )

    initial_memory = get_available_memory_mb()

    # Analyze zip structure FIRST to get accurate sizes
    print(f"\n{'='*70}")
    print("ANALYZING ZIP STRUCTURE")
    print(f"{'='*70}")

    with zipfile.ZipFile(zip_path, 'r') as zf:
        entries = [e for e in zf.infolist() if not e.is_dir()]
        total_files = len(entries)

        text_files = []
        binary_files = []
        for e in entries:
            ext = Path(e.filename).suffix.lower()
            if ext in TEXT_EXTENSIONS:
                text_files.append(e)
            else:
                binary_files.append(e)

        large_files = [e for e in text_files if e.file_size >= LARGE_FILE_THRESHOLD]
        small_files = [e for e in text_files if e.file_size < LARGE_FILE_THRESHOLD]

    # Calculate sizes (uncompressed = file_size, compressed = compress_size)
    compressed_size_mb = zip_path.stat().st_size / (1024 * 1024)
    total_uncompressed_mb = sum(e.file_size for e in entries) / (1024 * 1024)
    text_files_size_mb = sum(e.file_size for e in text_files) / (1024 * 1024)
    binary_files_size_mb = sum(e.file_size for e in binary_files) / (1024 * 1024)
    large_files_size_mb = sum(e.file_size for e in large_files) / (1024 * 1024)
    small_files_size_mb = sum(e.file_size for e in small_files) / (1024 * 1024)

    compression_ratio = total_uncompressed_mb / compressed_size_mb if compressed_size_mb > 0 else 1.0

    print(f"File: {zip_path}")
    print(f"Compressed size: {compressed_size_mb:.1f} MB")
    print(f"Uncompressed size: {total_uncompressed_mb:.1f} MB (ratio: {compression_ratio:.1f}x)")
    print(f"  - Text files: {text_files_size_mb:.1f} MB ({len(text_files)} files)")
    print(f"    - Large (>{LARGE_FILE_THRESHOLD//(1024*1024)}MB): {large_files_size_mb:.1f} MB ({len(large_files)} files)")
    print(f"    - Small: {small_files_size_mb:.1f} MB ({len(small_files)} files)")
    print(f"  - Binary files: {binary_files_size_mb:.1f} MB ({len(binary_files)} files)")
    print(f"Available memory: {initial_memory:.0f} MB")
    print(f"CPU cores: {multiprocessing.cpu_count()}")
    print(f"{'='*70}\n")

    # Initialize report with uncompressed sizes
    report = BenchmarkReport(
        zip_path=str(zip_path),
        zip_compressed_size_mb=compressed_size_mb,
        zip_uncompressed_size_mb=total_uncompressed_mb,
        total_files=total_files,
        text_files=len(text_files),
        binary_files=len(binary_files),
        large_files=len(large_files),
        small_files=len(small_files),
        text_files_size_mb=text_files_size_mb,
        binary_files_size_mb=binary_files_size_mb,
        large_files_size_mb=large_files_size_mb,
        small_files_size_mb=small_files_size_mb,
        cpu_count=multiprocessing.cpu_count(),
        platform=sys.platform,
        initial_available_memory_mb=initial_memory,
    )

    # Start memory monitoring BEFORE processing begins
    mem_monitor = MemoryMonitor(interval_seconds=0.5)
    mem_monitor.start()

    # Run the anonymizer
    start_time = time.time()
    try:
        success = process_zip(str(zip_path))
    finally:
        mem_monitor.stop()

    end_time = time.time()

    # Collect metrics - use UNCOMPRESSED size for throughput
    report.total_time_seconds = end_time - start_time
    report.overall_throughput_mb_s = total_uncompressed_mb / report.total_time_seconds if report.total_time_seconds > 0 else 0

    report.peak_memory_mb = mem_monitor.get_peak_used()
    report.min_available_memory_mb = mem_monitor.get_min_available()
    report.memory_samples = [asdict(s) for s in mem_monitor.samples[-100:]]  # Last 100 samples

    # Verify accuracy if expected counts provided
    if expected_counts:
        report.accuracy_verified = True
        # Read output and count patterns (simplified check)
        output_dir = zip_path.parent / (zip_path.stem + "_anonymized")
        if output_dir.exists():
            # Count REDACTED occurrences
            redacted_counts = defaultdict(int)
            for log_file in output_dir.rglob("*.log"):
                try:
                    content = log_file.read_text(encoding='utf-8', errors='ignore')
                    redacted_counts['email'] += content.count('@redacted.com')
                    redacted_counts['internal_ip'] += content.count('INTERNAL_IP_')
                    redacted_counts['password'] += content.count('PASSWORD_REDACTED')
                    redacted_counts['db_connection'] += content.count('DB_REDACTED')
                    redacted_counts['hostname'] += content.count('.redacted')
                    redacted_counts['mac_address'] += content.count('MAC_REDACTED')
                    redacted_counts['tableau_entity'] += content.count('TABLEAU_ENTITY_')
                    redacted_counts['api_key'] += content.count('API_KEY_REDACTED')
                    redacted_counts['username'] += content.count('USERNAME_')
                except Exception as e:
                    report.accuracy_errors.append(f"Error reading {log_file}: {e}")

            # Compare (allow some variance due to pattern overlap)
            for cat, expected in expected_counts.items():
                actual = redacted_counts.get(cat, 0)
                if actual < expected * 0.9:  # Allow 10% variance
                    report.accuracy_errors.append(
                        f"{cat}: expected ~{expected}, got {actual} (missing {expected - actual})"
                    )
                elif actual > expected * 1.1:
                    report.accuracy_errors.append(
                        f"{cat}: expected ~{expected}, got {actual} (extra {actual - expected})"
                    )

    return report


def print_report(report: BenchmarkReport):
    """Print a formatted benchmark report."""
    print(f"\n{'='*70}")
    print("BENCHMARK REPORT")
    print(f"{'='*70}")

    # Calculate compression ratio
    compression_ratio = report.zip_uncompressed_size_mb / report.zip_compressed_size_mb if report.zip_compressed_size_mb > 0 else 1.0

    print(f"\nFILE SUMMARY:")
    print(f"  Total files: {report.total_files}")
    print(f"  Text files: {report.text_files} (large: {report.large_files}, small: {report.small_files})")
    print(f"  Binary files: {report.binary_files}")
    print(f"  Compressed size: {report.zip_compressed_size_mb:.1f} MB")
    print(f"  Uncompressed size: {report.zip_uncompressed_size_mb:.1f} MB (ratio: {compression_ratio:.1f}x)")

    print(f"\nSIZE BREAKDOWN (uncompressed):")
    print(f"  Text files: {report.text_files_size_mb:.1f} MB")
    print(f"    - Large files: {report.large_files_size_mb:.1f} MB ({report.large_files} files)")
    print(f"    - Small files: {report.small_files_size_mb:.1f} MB ({report.small_files} files)")
    print(f"  Binary files: {report.binary_files_size_mb:.1f} MB")

    print(f"\nPERFORMANCE:")
    print(f"  Total time: {report.total_time_seconds:.1f} seconds ({report.total_time_seconds/60:.1f} min)")
    print(f"  Overall throughput: {report.overall_throughput_mb_s:.2f} MB/s (based on uncompressed size)")

    # Calculate what throughput would be needed to hit 30 min target
    if report.zip_uncompressed_size_mb > 0 and report.total_time_seconds > 0:
        target_30_min_throughput = report.zip_uncompressed_size_mb / (30 * 60)
        speedup_needed = target_30_min_throughput / report.overall_throughput_mb_s if report.overall_throughput_mb_s > 0 else 0
        print(f"  Target for 30 min: {target_30_min_throughput:.2f} MB/s ({speedup_needed:.1f}x speedup needed)")

    print(f"\nMEMORY:")
    print(f"  Initial available: {report.initial_available_memory_mb:.0f} MB")
    print(f"  Peak memory used: {report.peak_memory_mb:.0f} MB")
    print(f"  Min available: {report.min_available_memory_mb:.0f} MB")
    if report.initial_available_memory_mb > 0 and report.min_available_memory_mb > 0:
        memory_consumed = report.initial_available_memory_mb - report.min_available_memory_mb
        print(f"  Memory consumed: {memory_consumed:.0f} MB")

    print(f"\nSYSTEM:")
    print(f"  Platform: {report.platform}")
    print(f"  CPU cores: {report.cpu_count}")

    if report.accuracy_verified:
        print(f"\nACCURACY:")
        if report.accuracy_errors:
            print(f"  ISSUES FOUND ({len(report.accuracy_errors)}):")
            for err in report.accuracy_errors[:10]:
                print(f"    - {err}")
        else:
            print(f"  All patterns verified correctly!")

    print(f"\n{'='*70}")


def save_report(report: BenchmarkReport, output_path: Path):
    """Save report to JSON file."""
    with open(output_path, 'w') as f:
        json.dump(asdict(report), f, indent=2)
    print(f"\nReport saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark ZipLogsAnonymizer performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("zipfile", nargs="?", help="Path to zip file to benchmark")
    parser.add_argument("--output", "-o", help="Output path for JSON report")
    parser.add_argument(
        "--synthetic", "-s", type=float,
        help="Create synthetic test data of specified size (MB)"
    )

    args = parser.parse_args()

    expected_counts = None

    if args.synthetic:
        # Create synthetic test data
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "synthetic_test.zip"
            expected_counts = create_synthetic_test_zip(args.synthetic, zip_path)
            report = run_benchmark(zip_path, expected_counts)
            print_report(report)

            if args.output:
                save_report(report, Path(args.output))
    elif args.zipfile:
        # Benchmark existing file
        zip_path = Path(args.zipfile)
        if not zip_path.exists():
            print(f"Error: File not found: {zip_path}")
            sys.exit(1)

        report = run_benchmark(zip_path)
        print_report(report)

        if args.output:
            save_report(report, Path(args.output))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
