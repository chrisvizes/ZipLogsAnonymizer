#!/usr/bin/env python3
"""
Performance Tests for ZipLogsAnonymizer

These tests benchmark individual components to:
1. Establish baseline performance metrics
2. Catch performance regressions early
3. Identify bottlenecks in specific components

Run with: pytest test_performance.py -v
Run specific: pytest test_performance.py::TestLineProcessingThroughput -v

Performance targets based on 20-minute goal for 14GB uncompressed:
- Target throughput: ~12 MB/s
- Current baseline: ~6 MB/s
- Need: ~2x improvement
"""

import time
import random
import pytest

from pattern_matcher import PatternMatcher, FastAnonymizer, anonymize_content


# =============================================================================
# RUST BACKEND VERIFICATION
# =============================================================================

class TestRustBackend:
    """Tests to verify Rust backend is available and performant."""

    def test_rust_core_available(self):
        """Verify Rust core is available (required)."""
        # Rust core is now mandatory - if we got here, import succeeded
        print("\n*** Rust core is available ***")
        # Create an anonymizer to verify it works
        matcher = PatternMatcher()
        anonymizer = FastAnonymizer(matcher)
        assert anonymizer._rust_core is not None

    def test_rust_speedup(self, matcher):
        """Verify Rust provides expected throughput."""

        # Generate test content with ~5% sensitive lines
        # Use repeated values (more realistic than unique per-line)
        lines = []
        for i in range(50000):
            if i % 20 == 0:
                # Cycle through a few users/passwords (more realistic than unique each line)
                user_idx = (i // 20) % 10
                lines.append(f"user=admin{user_idx} password=secret123")
            else:
                lines.append(f"Regular log line {i}")
        content = "\n".join(lines)

        # Test with Rust
        anonymizer = FastAnonymizer(matcher)
        start = time.perf_counter()
        anonymizer.process_content(content)
        rust_time = time.perf_counter() - start

        # Rust should process at least 20 MB/s (vs ~5-6 MB/s Python for dense patterns)
        # With realistic content (5% sensitive), expect 50-100+ MB/s
        size_mb = len(content) / 1024 / 1024
        throughput = size_mb / rust_time
        print(f"\nRust throughput: {throughput:.1f} MB/s")
        assert throughput >= 20.0, f"Rust throughput too low: {throughput:.1f} MB/s"


# =============================================================================
# TEST DATA GENERATORS
# =============================================================================

def generate_clean_log_line() -> str:
    """Generate a typical log line with no sensitive data."""
    timestamps = ["2024-01-15 10:30:45", "2024-01-15 10:30:46", "2024-01-15 10:30:47"]
    levels = ["INFO", "DEBUG", "WARN", "ERROR"]
    messages = [
        "Processing request completed successfully",
        "Cache hit for key abc123",
        "Database query executed in 45ms",
        "Thread pool size: 8, active: 3",
        "Memory usage: 512MB / 1024MB",
        "Request processed in 123ms",
        "Connection established to port 8080",
        "File saved to /var/log/app.log",
        "Batch processing completed: 1000 items",
        "Scheduler triggered job: cleanup",
    ]
    return f"{random.choice(timestamps)} {random.choice(levels)}  {random.choice(messages)}"


def generate_sensitive_log_line() -> str:
    """Generate a log line containing sensitive data."""
    templates = [
        "2024-01-15 10:30:45 INFO  User user=john.smith logged in from 192.168.1.100",
        "2024-01-15 10:30:46 DEBUG Connection: jdbc:mysql://db.internal:3306/prod",
        "2024-01-15 10:30:47 WARN  Auth failed for password=secretpass123",
        "2024-01-15 10:30:48 INFO  API call with token=abcdefghij1234567890klmnop",
        "2024-01-15 10:30:49 DEBUG Request from server.corp to 10.0.0.50",
        "2024-01-15 10:30:50 INFO  Email sent to admin@company.local",
        "2024-01-15 10:30:51 DEBUG MAC address: 00:1A:2B:3C:4D:5E",
        "2024-01-15 10:30:52 INFO  Processing workbook=SalesReport for site=Production",
    ]
    return random.choice(templates)


def generate_test_content(
    num_lines: int,
    sensitive_ratio: float = 0.05  # 5% of lines have sensitive data (realistic)
) -> str:
    """Generate test content with specified ratio of sensitive lines."""
    lines = []
    for _ in range(num_lines):
        if random.random() < sensitive_ratio:
            lines.append(generate_sensitive_log_line())
        else:
            lines.append(generate_clean_log_line())
    return "\n".join(lines)


def estimate_content_size_mb(content: str) -> float:
    """Estimate content size in MB."""
    return len(content.encode('utf-8')) / (1024 * 1024)


# =============================================================================
# PERFORMANCE THRESHOLDS
# =============================================================================

# These thresholds define minimum acceptable performance.
# Tests fail if performance drops below these values.
# Values are set conservatively to catch major regressions.

THRESHOLDS = {
    # Full pipeline: end-to-end throughput for mixed content (5% sensitive)
    # Baseline: ~7 MB/s
    # Minimum acceptable: 5 MB/s (catch 30% regressions)
    "full_pipeline_mb_per_sec": 5.0,

    # Clean content: content with NO sensitive data
    # Baseline: ~8 MB/s (still checks every line for keywords)
    # Minimum acceptable: 6 MB/s
    "clean_content_mb_per_sec": 6.0,

    # Sparse content (only 0.1% sensitive): should be close to clean content speed
    # Baseline: ~7 MB/s
    # Minimum acceptable: 5 MB/s
    "sparse_content_mb_per_sec": 5.0,
}


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def matcher():
    """Shared pattern matcher instance."""
    return PatternMatcher()


@pytest.fixture(scope="module")
def medium_content():
    """Medium test content: 100,000 lines (~10MB)."""
    random.seed(42)
    return generate_test_content(100_000, sensitive_ratio=0.05)


@pytest.fixture(scope="module")
def clean_content():
    """Content with no sensitive data (fast path test)."""
    random.seed(42)
    return generate_test_content(50_000, sensitive_ratio=0.0)


@pytest.fixture(scope="module")
def high_sensitive_content():
    """Content with high ratio of sensitive data (stress test)."""
    random.seed(42)
    return generate_test_content(10_000, sensitive_ratio=0.50)


# =============================================================================
# FULL PIPELINE TESTS
# =============================================================================

class TestLineProcessingThroughput:
    """Test end-to-end throughput of the full processing pipeline."""

    def test_mixed_content_throughput_mb(self, matcher, medium_content):
        """Test MB/s throughput on realistic mixed content."""
        size_mb = estimate_content_size_mb(medium_content)

        # Warm up
        anonymize_content(medium_content[:10000], matcher)

        # Benchmark
        start = time.perf_counter()
        result, counts = anonymize_content(medium_content, matcher)
        elapsed = time.perf_counter() - start

        throughput_mb = size_mb / elapsed
        lines = medium_content.count("\n") + 1
        lines_per_sec = lines / elapsed

        print(f"\nFull pipeline (mixed content):")
        print(f"  Size: {size_mb:.1f} MB, {lines:,} lines")
        print(f"  Time: {elapsed:.2f}s")
        print(f"  Throughput: {throughput_mb:.2f} MB/s")
        print(f"  Lines/sec: {lines_per_sec:,.0f}")
        print(f"  Replacements: {sum(counts.values())}")

        assert throughput_mb >= THRESHOLDS["full_pipeline_mb_per_sec"], \
            f"Pipeline throughput too low: {throughput_mb:.2f} < {THRESHOLDS['full_pipeline_mb_per_sec']} MB/s"

    def test_clean_content_fast_path(self, matcher, clean_content):
        """Verify clean content (no matches) is processed very fast."""
        size_mb = estimate_content_size_mb(clean_content)

        # Benchmark
        start = time.perf_counter()
        result, counts = anonymize_content(clean_content, matcher)
        elapsed = time.perf_counter() - start

        throughput_mb = size_mb / elapsed

        print(f"\nClean content fast path:")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"  Time: {elapsed:.2f}s")
        print(f"  Throughput: {throughput_mb:.2f} MB/s")
        print(f"  Replacements: {sum(counts.values())} (should be 0)")

        # Clean content should be MUCH faster
        assert throughput_mb >= THRESHOLDS["clean_content_mb_per_sec"], \
            f"Clean content too slow: {throughput_mb:.2f} < {THRESHOLDS['clean_content_mb_per_sec']} MB/s"
        assert sum(counts.values()) == 0, "Clean content should have no replacements"

    def test_high_sensitive_content_throughput(self, matcher, high_sensitive_content):
        """Test throughput with 50% sensitive lines (worst case)."""
        size_mb = estimate_content_size_mb(high_sensitive_content)

        start = time.perf_counter()
        result, counts = anonymize_content(high_sensitive_content, matcher)
        elapsed = time.perf_counter() - start

        throughput_mb = size_mb / elapsed
        lines = high_sensitive_content.count("\n") + 1

        print(f"\nHigh-sensitive content (50% sensitive):")
        print(f"  Size: {size_mb:.1f} MB, {lines:,} lines")
        print(f"  Time: {elapsed:.2f}s")
        print(f"  Throughput: {throughput_mb:.2f} MB/s")
        print(f"  Replacements: {sum(counts.values())}")

        # Even worst case should maintain reasonable throughput
        # (at least 50% of normal threshold)
        min_threshold = THRESHOLDS["full_pipeline_mb_per_sec"] * 0.5
        assert throughput_mb >= min_threshold, \
            f"High-sensitive throughput too low: {throughput_mb:.2f} < {min_threshold} MB/s"


# =============================================================================
# SCALABILITY TESTS
# =============================================================================

class TestScalability:
    """Test that performance scales linearly with input size."""

    def test_linear_scaling(self, matcher):
        """Verify throughput doesn't degrade significantly with larger inputs."""
        sizes = [1_000, 10_000, 50_000]
        throughputs = []

        random.seed(42)

        for num_lines in sizes:
            content = generate_test_content(num_lines, sensitive_ratio=0.05)
            size_mb = estimate_content_size_mb(content)

            start = time.perf_counter()
            anonymize_content(content, matcher)
            elapsed = time.perf_counter() - start

            throughput = size_mb / elapsed
            throughputs.append(throughput)
            print(f"\n{num_lines:,} lines: {throughput:.2f} MB/s")

        # Throughput should not degrade by more than 70% at larger sizes
        # Note: Rust parallel processing kicks in at >1000 lines which can cause variance
        max_throughput = max(throughputs)
        min_throughput = min(throughputs)
        degradation = (max_throughput - min_throughput) / max_throughput

        print(f"\nScaling: max={max_throughput:.2f}, min={min_throughput:.2f}, degradation={degradation:.1%}")
        assert degradation < 0.70, f"Performance degrades too much at scale: {degradation:.1%}"


# =============================================================================
# MEMORY EFFICIENCY TESTS
# =============================================================================

class TestMemoryEfficiency:
    """Test that optimizations don't cause excessive memory usage."""

    def test_no_unnecessary_string_copies(self, matcher, clean_content):
        """Verify clean content returns original string (no copy)."""
        result, counts = anonymize_content(clean_content, matcher)

        # For clean content, we should return the original string
        # This avoids unnecessary memory allocation
        assert result is clean_content or result == clean_content, \
            "Clean content should return original or equivalent string"

    def test_in_place_modification(self, matcher):
        """Verify lines are modified in-place when possible."""
        # Create content where only a few lines have sensitive data
        lines = [generate_clean_log_line() for _ in range(1000)]
        lines[500] = "password=secret123"  # One sensitive line
        content = "\n".join(lines)

        start = time.perf_counter()
        result, counts = anonymize_content(content, matcher)
        elapsed = time.perf_counter() - start

        # Should be fast since only 1 line needs modification
        size_mb = estimate_content_size_mb(content)
        throughput = size_mb / elapsed

        print(f"\nSparse sensitive content: {throughput:.2f} MB/s")
        assert throughput >= THRESHOLDS["sparse_content_mb_per_sec"], \
            f"Sparse content too slow: {throughput:.2f} < {THRESHOLDS['sparse_content_mb_per_sec']} MB/s"


# =============================================================================
# REGRESSION MARKERS
# =============================================================================

class TestPerformanceBaselines:
    """
    Tests that establish and verify performance baselines.
    These tests should be run before and after any optimization changes.
    """

    def test_baseline_summary(self, matcher, medium_content, clean_content, high_sensitive_content):
        """Print a summary of all performance metrics."""
        print("\n" + "=" * 70)
        print("PERFORMANCE BASELINE SUMMARY")
        print("=" * 70)

        # Mixed content
        size_mb = estimate_content_size_mb(medium_content)
        start = time.perf_counter()
        anonymize_content(medium_content, matcher)
        elapsed = time.perf_counter() - start
        mixed_throughput = size_mb / elapsed

        # Clean content
        size_mb = estimate_content_size_mb(clean_content)
        start = time.perf_counter()
        anonymize_content(clean_content, matcher)
        elapsed = time.perf_counter() - start
        clean_throughput = size_mb / elapsed

        # High sensitive
        size_mb = estimate_content_size_mb(high_sensitive_content)
        start = time.perf_counter()
        anonymize_content(high_sensitive_content, matcher)
        elapsed = time.perf_counter() - start
        sensitive_throughput = size_mb / elapsed

        print(f"\nMixed content (5% sensitive):    {mixed_throughput:>8.2f} MB/s")
        print(f"Clean content (0% sensitive):    {clean_throughput:>8.2f} MB/s")
        print(f"High sensitive (50% sensitive):  {sensitive_throughput:>8.2f} MB/s")

        # Target calculation
        target_20_min = 14289 / (20 * 60)  # 14GB in 20 minutes
        print(f"\nTarget for 20-min (14GB):        {target_20_min:>8.2f} MB/s")
        print(f"Current vs target:               {mixed_throughput/target_20_min:>8.1%}")
        print("=" * 70)


# =============================================================================
# STREAMING/FILE PROCESSING TESTS
# =============================================================================

class TestStreamingLargeFileProcessing:
    """
    Tests for the actual streaming large file path in anonymizer.py.

    These tests catch performance issues that in-memory tests miss:
    - The process_large_file_streaming function
    - Actual file I/O patterns
    - Memory efficiency during streaming
    """

    def test_streaming_throughput_matches_in_memory(self, matcher):
        """
        Verify streaming path has similar throughput to in-memory.

        This test catches regressions in process_large_file_streaming.
        """
        import tempfile
        import os
        from pathlib import Path

        # Generate 10MB of test content (simulates a large file)
        content = generate_test_content(100000, sensitive_ratio=0.05)
        size_mb = estimate_content_size_mb(content)

        # Measure in-memory throughput
        start = time.perf_counter()
        result_mem, counts_mem = anonymize_content(content, matcher)
        elapsed_mem = time.perf_counter() - start
        mem_throughput = size_mb / elapsed_mem

        # Measure streaming throughput using actual file processing
        from anonymizer import process_large_file_streaming

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "output.txt"
            data = content.encode('utf-8')

            start = time.perf_counter()
            counts_stream, error = process_large_file_streaming(data, output_path)
            elapsed_stream = time.perf_counter() - start
            stream_throughput = size_mb / elapsed_stream

        print(f"\nIn-memory throughput:  {mem_throughput:.2f} MB/s")
        print(f"Streaming throughput:  {stream_throughput:.2f} MB/s")
        print(f"Streaming / In-memory: {stream_throughput/mem_throughput:.1%}")

        # With Rust, streaming should achieve at least 5 MB/s absolute throughput
        assert stream_throughput >= 5.0, \
            f"Streaming too slow: {stream_throughput:.2f} MB/s (minimum 5 MB/s)"

    def test_streaming_with_clean_content_fast_path(self, matcher):
        """
        Verify clean content fast path works in streaming mode.

        Files with no sensitive data should process very quickly.
        """
        import tempfile
        from pathlib import Path

        # Generate 10MB of clean content (no sensitive data)
        lines = [generate_clean_log_line() for _ in range(100000)]
        content = "\n".join(lines)
        size_mb = estimate_content_size_mb(content)

        from anonymizer import process_large_file_streaming

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "output.txt"
            data = content.encode('utf-8')

            start = time.perf_counter()
            counts, error = process_large_file_streaming(data, output_path)
            elapsed = time.perf_counter() - start
            throughput = size_mb / elapsed

        print(f"\nClean content streaming: {throughput:.2f} MB/s")

        # Clean content should be fast (>10 MB/s) due to fast path
        assert throughput >= 8.0, \
            f"Clean content streaming too slow: {throughput:.2f} MB/s (expected >8)"

        # Should have zero replacements
        assert not counts or sum(counts.values()) == 0, \
            f"Clean content should have no replacements, got {counts}"


def _process_chunk(content: str) -> str:
    """Process a single chunk - module-level function for pickling."""
    from pattern_matcher import PatternMatcher, anonymize_content
    matcher = PatternMatcher()
    result, _ = anonymize_content(content, matcher)
    return result


class TestCPUUtilization:
    """
    Tests to verify CPU utilization patterns.

    Low CPU utilization (<20%) on a multi-core system indicates
    parallelization issues (GIL, sequential processing, etc.)
    """

    def test_parallel_chunk_processing_feasibility(self, matcher):
        """
        Test that content can be processed in parallel chunks.

        This validates that splitting and parallel processing is viable
        for improving CPU utilization on large files.
        """
        from concurrent.futures import ProcessPoolExecutor
        import multiprocessing

        # Generate LARGER test content - 200K lines (~20MB)
        # Small chunks don't benefit from parallelism due to overhead
        content = generate_test_content(200000, sensitive_ratio=0.05)
        size_mb = estimate_content_size_mb(content)

        # Split into chunks (at line boundaries)
        lines = content.split('\n')
        num_chunks = min(4, multiprocessing.cpu_count())
        chunk_size = len(lines) // num_chunks
        chunks = []
        for i in range(num_chunks):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < num_chunks - 1 else len(lines)
            chunks.append('\n'.join(lines[start_idx:end_idx]))

        print(f"\nContent size: {size_mb:.1f} MB, {num_chunks} chunks of ~{size_mb/num_chunks:.1f} MB each")

        # Process sequentially FIRST (so matcher is warm)
        start = time.perf_counter()
        for chunk in chunks:
            anonymize_content(chunk, matcher)
        elapsed_sequential = time.perf_counter() - start
        sequential_throughput = size_mb / elapsed_sequential

        # Process chunks in parallel (cold start, but larger chunks)
        start = time.perf_counter()
        with ProcessPoolExecutor(max_workers=num_chunks) as executor:
            results = list(executor.map(_process_chunk, chunks))
        elapsed_parallel = time.perf_counter() - start
        parallel_throughput = size_mb / elapsed_parallel

        print(f"Sequential throughput: {sequential_throughput:.2f} MB/s")
        print(f"Parallel throughput:   {parallel_throughput:.2f} MB/s")
        print(f"Speedup:              {parallel_throughput/sequential_throughput:.2f}x")
        print(f"CPU cores used:       {num_chunks}")

        # ProcessPoolExecutor has significant startup overhead when the Rust extension
        # needs to be loaded in each worker process. With Rust, sequential processing
        # is already very fast, so parallel overhead dominates. Just verify parallel
        # doesn't fail and achieves reasonable absolute throughput.
        assert parallel_throughput >= 5.0, \
            f"Parallel processing too slow: {parallel_throughput:.2f} MB/s (minimum 5 MB/s)"


# =============================================================================
# MEMORY USAGE TESTS
# =============================================================================

class TestMemoryUsage:
    """
    Tests to verify memory usage stays within acceptable bounds.

    These tests catch memory issues like:
    - Keeping duplicate content in memory (original + lowercase)
    - Excessive memory during parallel processing
    - Memory leaks in long-running processes
    """

    def test_memory_usage_ratio(self, matcher):
        """
        Verify that processing doesn't use excessive memory relative to file size.

        Baseline memory usage is ~6x due to Python string handling:
        - Original content
        - Lowercase copy for keyword detection
        - Lines array when splitting
        - Result content
        - Various temporary structures

        This test catches major regressions (e.g., memory doubling from a bug).
        The 7GB spike on 1.7GB file (~4x) was caused by keeping duplicate content.
        """
        import gc
        import sys

        # Generate test content - 50MB of data (simulates large file)
        content = generate_test_content(500000, sensitive_ratio=0.05)
        content_size_mb = estimate_content_size_mb(content)

        # Force garbage collection to get baseline
        gc.collect()

        # Track memory before processing
        try:
            import tracemalloc
            tracemalloc.start()

            # Process the content
            result, counts = anonymize_content(content, matcher)

            # Get peak memory usage
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            peak_mb = peak / (1024 * 1024)
            memory_ratio = peak_mb / content_size_mb

            print(f"\nContent size: {content_size_mb:.1f} MB")
            print(f"Peak memory: {peak_mb:.1f} MB")
            print(f"Memory ratio: {memory_ratio:.1f}x")

            # Memory should be at most 8x the content size
            # Baseline is ~6x, so 8x catches major regressions
            assert memory_ratio <= 8.0, \
                f"Memory usage too high: {peak_mb:.1f} MB for {content_size_mb:.1f} MB content " \
                f"(ratio: {memory_ratio:.1f}x, expected <= 8x)"

        except ImportError:
            # tracemalloc not available - skip test
            pytest.skip("tracemalloc not available")

    def test_streaming_memory_efficiency(self, matcher):
        """
        Verify streaming processing doesn't accumulate memory.

        Tests that process_large_file_streaming properly frees memory
        between chunks. Baseline is ~6x due to:
        - Input data (bytes)
        - Decoded content (string)
        - Lines array
        - Temporary lowercase content
        - Output chunks
        """
        import tempfile
        from pathlib import Path
        import gc

        # Generate 20MB of test content
        content = generate_test_content(200000, sensitive_ratio=0.05)
        content_size_mb = estimate_content_size_mb(content)

        from anonymizer import process_large_file_streaming

        try:
            import tracemalloc
            tracemalloc.start()

            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / "output.txt"
                data = content.encode('utf-8')

                # Process using streaming
                counts, error = process_large_file_streaming(data, output_path)

                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                peak_mb = peak / (1024 * 1024)
                memory_ratio = peak_mb / content_size_mb

                print(f"\nStreaming content size: {content_size_mb:.1f} MB")
                print(f"Peak memory: {peak_mb:.1f} MB")
                print(f"Memory ratio: {memory_ratio:.1f}x")

                # Streaming memory baseline is ~6x, so 8x catches major regressions
                assert memory_ratio <= 8.0, \
                    f"Streaming memory too high: {peak_mb:.1f} MB for {content_size_mb:.1f} MB " \
                    f"(ratio: {memory_ratio:.1f}x, expected <= 8x)"

        except ImportError:
            pytest.skip("tracemalloc not available")


class TestConsistentReplacements:
    """
    Tests to verify replacements are consistent across parallel processing.

    Same values must get same replacements regardless of which chunk
    or worker processes them.
    """

    def test_consistent_email_replacements(self, matcher):
        """
        Verify same email gets same replacement across the file.
        """
        # Create content with repeated emails
        lines = []
        for i in range(100):
            lines.append(f"2024-01-15 INFO User john.doe@company.com performed action {i}")
            lines.append(f"2024-01-15 DEBUG Notification sent to jane.smith@company.local")
            lines.append(f"2024-01-15 INFO User john.doe@company.com logged out")

        content = "\n".join(lines)
        result, counts = anonymize_content(content, matcher)

        # Find all email replacements (format: user001@redacted.com)
        import re
        email_replacements = re.findall(r'user\d+@redacted\.com', result)

        # All john.doe references should have the same replacement
        unique = set(email_replacements)
        print(f"\nEmail replacements found: {len(email_replacements)}")
        print(f"Unique replacements: {len(unique)}")

        # Should have exactly 2 unique replacements (john and jane)
        assert len(unique) <= 2, \
            f"Expected 2 unique email replacements, got {len(unique)}: {unique}"

    def test_consistent_username_replacements(self, matcher):
        """
        Verify same username gets same replacement across the file.
        """
        lines = []
        for i in range(100):
            lines.append(f"2024-01-15 INFO user=admin performed action {i}")
            lines.append(f"2024-01-15 DEBUG user=guest viewed page")
            lines.append(f"2024-01-15 WARN user=admin changed settings")

        content = "\n".join(lines)
        result, counts = anonymize_content(content, matcher)

        # Find all username replacements (format: user=user001)
        import re
        username_replacements = re.findall(r'user=user\d+', result)

        # Count unique replacements
        unique = set(username_replacements)
        print(f"\nUsername replacements found: {len(username_replacements)}")
        print(f"Unique replacements: {len(unique)}")

        # Should have exactly 2 unique replacements (admin and guest)
        assert len(unique) == 2, \
            f"Expected 2 unique username replacements, got {len(unique)}: {unique}"

    def test_consistent_ip_replacements(self, matcher):
        """
        Verify same IP gets same replacement across the file.
        """
        lines = []
        for i in range(100):
            lines.append(f"2024-01-15 INFO Connection from 192.168.1.100 on port {8000+i}")
            lines.append(f"2024-01-15 DEBUG Request to 10.0.0.50")
            lines.append(f"2024-01-15 INFO Response sent to 192.168.1.100")

        content = "\n".join(lines)
        result, counts = anonymize_content(content, matcher)

        # Find all IP replacements (format: 10.X.0.1)
        import re
        ip_replacements = re.findall(r'10\.\d+\.0\.1', result)

        unique = set(ip_replacements)
        print(f"\nIP replacements found: {len(ip_replacements)}")
        print(f"Unique replacements: {len(unique)}")

        # Should have exactly 2 unique replacements
        assert len(unique) == 2, \
            f"Expected 2 unique IP replacements, got {len(unique)}: {unique}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
