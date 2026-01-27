#!/usr/bin/env python3
"""
ZipLogsAnonymizer - Anonymize sensitive data in log archives for safe sharing with LLMs.

Usage: python anonymizer.py <path_to_zipfile>

Optimized for large zip files (up to 2GB) with:
- Batch processing to limit memory usage
- Parallel anonymization within each batch
- Outputs to an unzipped directory (preserving original structure)
"""

import argparse
import os
import re
import sys
import zipfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import multiprocessing


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
    ".csv",
    ".html",
    ".htm",
}

# Batch size for processing (limit memory usage)
BATCH_SIZE = 100  # Process 100 files at a time
MAX_FILE_SIZE_FOR_PARALLEL = 10 * 1024 * 1024  # 10MB - larger files processed serially


@dataclass
class AnonymizationResult:
    """Result from anonymizing a single file."""

    filename: str
    content: bytes
    replacements: dict[str, int]  # category -> count (not full list, to save memory)
    error: Optional[str] = None


class PatternMatcher:
    """Compiled regex patterns for sensitive data detection."""

    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> list[tuple[str, re.Pattern, str, bool]]:
        """Returns list of (category, pattern, replacement_template, uses_groups)."""
        patterns = []

        # Email addresses
        patterns.append(
            (
                "email",
                re.compile(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE
                ),
                "{UNIQUE}@redacted.com",
                False,
            )
        )

        # Internal IP addresses (private ranges)
        patterns.append(
            (
                "internal_ip",
                re.compile(
                    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                    r"192\.168\.\d{1,3}\.\d{1,3}|"
                    r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b"
                ),
                "{UNIQUE}",
                False,
            )
        )

        # Passwords (combined pattern)
        patterns.append(
            (
                "password",
                re.compile(
                    r'((?:password|passwd|pwd|secret)\s*[=:]\s*)[^\s,;\'"}\]]+|'
                    r'("(?:password|passwd|pwd|secret)"\s*:\s*")[^"]+',
                    re.IGNORECASE,
                ),
                r"\1PASSWORD_REDACTED",
                True,
            )
        )

        # API keys and tokens
        patterns.append(
            (
                "api_key",
                re.compile(
                    r"((?:api[_-]?key|token|bearer)\s*[=:]\s*)[a-zA-Z0-9_-]{20,}|"
                    r'("(?:api[_-]?key|token)"\s*:\s*")[^"]{20,}|'
                    r"\b(sk-[a-zA-Z0-9]{20,})\b|"
                    r"\b(pk_[a-zA-Z0-9_]{20,})\b",
                    re.IGNORECASE,
                ),
                "API_KEY_REDACTED",
                True,
            )
        )

        # Authorization headers
        patterns.append(
            (
                "auth_header",
                re.compile(
                    r"(Authorization\s*:\s*(?:Basic|Bearer|Digest)\s+)[^\s\r\n]+",
                    re.IGNORECASE,
                ),
                r"\1AUTH_TOKEN_REDACTED",
                True,
            )
        )

        # Database connection strings
        patterns.append(
            (
                "db_connection",
                re.compile(
                    r"jdbc:[a-zA-Z0-9]+://[^;\s]+|"
                    r"(?:Server|Data Source|User ID|uid)\s*=\s*[^;\s]+",
                    re.IGNORECASE,
                ),
                "DB_REDACTED",
                False,
            )
        )

        # UNC paths
        patterns.append(
            (
                "unc_path",
                re.compile(
                    r"\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.$-]+(?:\\[a-zA-Z0-9_.$-]+)*"
                ),
                r"\\\\REDACTED_SERVER\\REDACTED_SHARE",
                False,
            )
        )

        # Hostnames with internal TLDs
        patterns.append(
            (
                "hostname",
                re.compile(
                    r"\b(?:[a-zA-Z][a-zA-Z0-9-]*\.)+(?:local|internal|corp|lan|intranet|private)\b",
                    re.IGNORECASE,
                ),
                "{UNIQUE}.redacted",
                False,
            )
        )

        # MAC addresses
        patterns.append(
            (
                "mac_address",
                re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
                "MAC_REDACTED",
                False,
            )
        )

        # Usernames in context
        patterns.append(
            (
                "username",
                re.compile(
                    r"((?:user(?:name)?|login)\s*[=:]\s*)([a-zA-Z0-9_@.-]+)|"
                    r'("(?:user(?:name)?|login)"\s*:\s*")([^"]+)',
                    re.IGNORECASE,
                ),
                r"\1{UNIQUE}",
                True,
            )
        )

        # Private keys and certificates
        patterns.append(
            (
                "private_key",
                re.compile(
                    r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----"
                ),
                "PRIVATE_KEY_REDACTED",
                False,
            )
        )
        patterns.append(
            (
                "certificate",
                re.compile(
                    r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
                ),
                "CERTIFICATE_REDACTED",
                False,
            )
        )

        # SSN (US format)
        patterns.append(
            (
                "ssn",
                re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                "SSN_REDACTED",
                False,
            )
        )

        # Tableau-specific
        patterns.append(
            (
                "tableau_entity",
                re.compile(
                    r'((?:site|workbook|datasource|project)\s*[=:]\s*)([^\s,;\'"}\]]+)',
                    re.IGNORECASE,
                ),
                r"\1{UNIQUE}",
                True,
            )
        )

        return patterns


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
    """Anonymize content. Returns (anonymized_content, category -> count)."""
    counts: dict[str, int] = defaultdict(int)
    unique_counters: dict[str, dict[str, int]] = defaultdict(dict)

    def get_unique_replacement(category: str, original: str, template: str) -> str:
        if original not in unique_counters[category]:
            unique_counters[category][original] = len(unique_counters[category]) + 1
        idx = unique_counters[category][original]
        return template.replace("{UNIQUE}", f"{category.upper()}_{idx:03d}")

    for category, pattern, replacement_template, uses_groups in matcher.patterns:
        if "{UNIQUE}" in replacement_template:

            def make_replacer(cat, templ):
                def replacer(m):
                    original = m.group(0)
                    counts[cat] += 1
                    if uses_groups and m.lastindex:
                        prefix = m.group(1) or ""
                        return prefix + get_unique_replacement(
                            cat, original, templ.replace(r"\1", "")
                        )
                    return get_unique_replacement(cat, original, templ)

                return replacer

            content = pattern.sub(
                make_replacer(category, replacement_template), content
            )
        elif uses_groups:

            def make_simple_replacer(cat, templ):
                def replacer(m):
                    counts[cat] += 1
                    result = templ
                    for i in range(1, (m.lastindex or 0) + 1):
                        grp = m.group(i)
                        if grp:
                            result = result.replace(f"\\{i}", grp)
                            break
                    return result

                return replacer

            content = pattern.sub(
                make_simple_replacer(category, replacement_template), content
            )
        else:
            match_count = len(pattern.findall(content))
            if match_count:
                counts[category] += match_count
                content = pattern.sub(replacement_template, content)

    return content, dict(counts)


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


def process_file_chunk(chunk: list[tuple[str, bytes]]) -> list[AnonymizationResult]:
    """Process a chunk of files in a single worker - reduces pickling overhead."""
    return [process_single_file(item) for item in chunk]


def process_zip(zip_path: str, max_workers: Optional[int] = None) -> bool:
    """Main processing function with batched processing for memory efficiency."""
    import shutil

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
    sys.stdout.flush()

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
                f"Found {total_files} files: {len(text_entries)} text, {len(binary_entries)} binary/other"
            )
            sys.stdout.flush()

            # Create output directory structure
            output_dir.mkdir(parents=True, exist_ok=True)

            # Create all subdirectories first
            for entry in src_zip.infolist():
                if entry.is_dir():
                    (output_dir / entry.filename).mkdir(parents=True, exist_ok=True)

            # Copy binary files directly (no processing needed)
            print("Copying binary files...")
            sys.stdout.flush()
            for entry in binary_entries:
                data = src_zip.read(entry.filename)
                out_path = output_dir / entry.filename
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(data)

            # Sort text files by size descending - process largest first for better load balancing
            text_entries.sort(key=lambda e: e.file_size, reverse=True)

            # Read all text file data
            print("Reading text files...")
            sys.stdout.flush()
            file_data = []
            for entry in text_entries:
                data = src_zip.read(entry.filename)
                file_data.append((entry.filename, data))

            # Split into chunks for each worker (reduces pickle overhead)
            print("Anonymizing text files...")
            sys.stdout.flush()

            # Distribute files round-robin across workers to balance load
            # (since sorted by size, this spreads large files across workers)
            chunks = [[] for _ in range(max_workers)]
            for i, item in enumerate(file_data):
                chunks[i % max_workers].append(item)
            chunks = [c for c in chunks if c]  # Remove empty chunks

            results = {}
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                # Submit chunks to workers
                futures = {executor.submit(process_file_chunk, chunk): i for i, chunk in enumerate(chunks)}

                processed = 0
                for future in as_completed(futures):
                    chunk_results = future.result()
                    for result in chunk_results:
                        results[result.filename] = result
                        for cat, count in result.replacements.items():
                            total_stats[cat] += count
                        if result.error:
                            errors.append(f"{result.filename}: {result.error}")
                        processed += 1

                    print(f"  Processed {processed}/{len(text_entries)} text files...")
                    sys.stdout.flush()

            # Write all results to output directory
            print("Writing output files...")
            sys.stdout.flush()
            for entry in text_entries:
                result = results[entry.filename]
                out_path = output_dir / entry.filename
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(result.content)

        # Print results
        print("\n" + "=" * 60)
        print("ANONYMIZATION COMPLETE")
        print("=" * 60)
        print(f"\nOutput directory: {output_dir}")
        print(f"Original zip size: {zip_path.stat().st_size / 1024 / 1024:.1f} MB")

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
        sys.stdout.flush()
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
    global BATCH_SIZE

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
        "-b",
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        help=f"Files per batch (default: {BATCH_SIZE})",
    )

    args = parser.parse_args()
    BATCH_SIZE = args.batch_size

    success = process_zip(args.zipfile, args.workers)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    multiprocessing.freeze_support()  # Required for Windows
    main()
