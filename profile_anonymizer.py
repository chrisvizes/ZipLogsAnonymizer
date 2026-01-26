#!/usr/bin/env python3
"""Profile the anonymizer to understand performance bottlenecks."""

import time
import zipfile
from pathlib import Path
from anonymizer import (
    PatternMatcher, anonymize_content, process_single_file,
    TEXT_EXTENSIONS, is_likely_binary
)


def profile_single_file(filename: str, data: bytes, matcher: PatternMatcher) -> dict:
    """Profile a single file's processing and return timing breakdown."""
    timings = {}

    # Binary check
    start = time.perf_counter()
    is_binary = is_likely_binary(data)
    timings['binary_check'] = time.perf_counter() - start

    if is_binary:
        return {'skipped': True, 'reason': 'binary', **timings}

    # Decode
    start = time.perf_counter()
    content = None
    for encoding in ["utf-8", "utf-16", "latin-1", "cp1252"]:
        try:
            content = data.decode(encoding)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    timings['decode'] = time.perf_counter() - start

    if content is None:
        return {'skipped': True, 'reason': 'decode_failed', **timings}

    # Anonymize (the CPU-intensive part)
    start = time.perf_counter()
    anonymized, counts = anonymize_content(content, matcher)
    timings['anonymize'] = time.perf_counter() - start

    # Encode
    start = time.perf_counter()
    _ = anonymized.encode("utf-8")
    timings['encode'] = time.perf_counter() - start

    timings['total'] = sum(timings.values())
    timings['content_size'] = len(data)
    timings['replacements'] = sum(counts.values())

    return timings


def profile_zip(zip_path: str, max_files: int = 50):
    """Profile processing of files from a zip."""
    zip_path = Path(zip_path)
    matcher = PatternMatcher()

    print(f"Profiling {zip_path.name} (first {max_files} text files)...\n")

    results = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        entries = [e for e in zf.infolist() if not e.is_dir()]
        text_entries = [e for e in entries if Path(e.filename).suffix.lower() in TEXT_EXTENSIONS]

        print(f"Found {len(text_entries)} text files\n")

        # Profile individual files
        for i, entry in enumerate(text_entries[:max_files]):
            data = zf.read(entry.filename)
            timings = profile_single_file(entry.filename, data, matcher)
            timings['filename'] = entry.filename
            results.append(timings)

            if (i + 1) % 10 == 0:
                print(f"  Profiled {i + 1}/{min(max_files, len(text_entries))} files...")

    # Analyze results
    print("\n" + "=" * 70)
    print("PROFILING RESULTS")
    print("=" * 70)

    processed = [r for r in results if not r.get('skipped')]
    skipped = [r for r in results if r.get('skipped')]

    print(f"\nFiles processed: {len(processed)}, skipped: {len(skipped)}")

    if processed:
        # Timing breakdown
        total_binary_check = sum(r['binary_check'] for r in processed)
        total_decode = sum(r['decode'] for r in processed)
        total_anonymize = sum(r['anonymize'] for r in processed)
        total_encode = sum(r['encode'] for r in processed)
        total_time = sum(r['total'] for r in processed)

        print(f"\nTiming breakdown (total across {len(processed)} files):")
        print(f"  Binary check:  {total_binary_check*1000:8.2f} ms ({total_binary_check/total_time*100:5.1f}%)")
        print(f"  Decode:        {total_decode*1000:8.2f} ms ({total_decode/total_time*100:5.1f}%)")
        print(f"  Anonymize:     {total_anonymize*1000:8.2f} ms ({total_anonymize/total_time*100:5.1f}%)")
        print(f"  Encode:        {total_encode*1000:8.2f} ms ({total_encode/total_time*100:5.1f}%)")
        print(f"  TOTAL:         {total_time*1000:8.2f} ms")

        # Per-file stats
        avg_time = total_time / len(processed) * 1000
        total_size = sum(r['content_size'] for r in processed)
        total_replacements = sum(r['replacements'] for r in processed)

        print(f"\nPer-file averages:")
        print(f"  Avg time per file:   {avg_time:.2f} ms")
        print(f"  Avg file size:       {total_size/len(processed)/1024:.1f} KB")
        print(f"  Total replacements:  {total_replacements}")

        # Throughput
        print(f"\nThroughput:")
        print(f"  Files/second:        {len(processed)/total_time:.1f}")
        print(f"  MB/second:           {total_size/1024/1024/total_time:.2f}")

        # Slowest files
        slowest = sorted(processed, key=lambda x: x['anonymize'], reverse=True)[:5]
        print(f"\nSlowest files (by anonymize time):")
        for r in slowest:
            print(f"  {r['anonymize']*1000:6.1f} ms - {r['content_size']/1024:6.1f} KB - {Path(r['filename']).name}")

    print("=" * 70)

    return results


def profile_pattern_matching():
    """Profile individual pattern matching to find slow patterns."""
    from anonymizer import PatternMatcher
    import re

    # Create test content with various sensitive data
    test_content = """
    user=admin@company.local password=secret123 email=test@example.com
    Server: 192.168.1.100 connected to 10.0.0.50
    jdbc:mysql://localhost:3306/mydb?user=root
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    site=CustomerSite workbook=SalesReport project=Marketing
    MAC: 00:1A:2B:3C:4D:5E hostname: server.internal
    """ * 100  # Repeat to make it substantial

    matcher = PatternMatcher()

    print("\nPattern matching performance (on ~10KB test content):")
    print("-" * 60)

    pattern_times = []
    for category, pattern, replacement, uses_groups in matcher.patterns:
        start = time.perf_counter()
        matches = pattern.findall(test_content)
        elapsed = time.perf_counter() - start
        pattern_times.append((category, elapsed * 1000, len(matches)))

    # Sort by time
    pattern_times.sort(key=lambda x: x[1], reverse=True)

    print(f"{'Pattern':<20} {'Time (ms)':<12} {'Matches':<10}")
    print("-" * 60)
    for cat, ms, count in pattern_times:
        print(f"{cat:<20} {ms:>8.3f} ms  {count:>6}")

    total_ms = sum(t[1] for t in pattern_times)
    print("-" * 60)
    print(f"{'TOTAL':<20} {total_ms:>8.3f} ms")


if __name__ == "__main__":
    import sys

    # Profile patterns first
    profile_pattern_matching()

    # Profile zip if provided
    if len(sys.argv) > 1:
        print("\n")
        profile_zip(sys.argv[1], max_files=50)
    else:
        print("\nUsage: python profile_anonymizer.py <zipfile>")
        print("       (will profile first 50 text files)")
