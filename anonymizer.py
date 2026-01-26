#!/usr/bin/env python3
"""
ZipLogsAnonymizer - Anonymize sensitive data in log archives for safe sharing with LLMs.

Usage: python anonymizer.py <path_to_zipfile>

This script extracts a zip file, anonymizes sensitive data in all text-based files,
and creates a new anonymized zip file ready for sharing.
"""

import argparse
import json
import os
import re
import shutil
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Callable


class ReplacementMapper:
    """Maintains consistent mappings from original values to anonymized replacements."""

    def __init__(self):
        self.mappings: dict[str, dict[str, str]] = defaultdict(dict)
        self.counters: dict[str, int] = defaultdict(int)
        self.stats: dict[str, int] = defaultdict(int)

    def get_replacement(self, category: str, original: str, prefix: str) -> str:
        """Get or create a consistent replacement for an original value."""
        if original not in self.mappings[category]:
            self.counters[category] += 1
            self.mappings[category][original] = f"{prefix}_{self.counters[category]:03d}"
        self.stats[category] += 1
        return self.mappings[category][original]

    def get_stats(self) -> dict[str, int]:
        """Return replacement statistics."""
        return dict(self.stats)

    def get_unique_counts(self) -> dict[str, int]:
        """Return count of unique values replaced per category."""
        return {cat: len(vals) for cat, vals in self.mappings.items()}


class LogAnonymizer:
    """Handles anonymization of log file contents."""

    # File extensions to process
    TEXT_EXTENSIONS = {'.log', '.txt', '.json', '.xml', '.yml', '.yaml', '.properties', '.conf', '.config', '.csv'}

    def __init__(self):
        self.mapper = ReplacementMapper()
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns for sensitive data detection."""

        # Email addresses
        self.email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        )

        # Internal IP addresses (private ranges)
        self.internal_ip_pattern = re.compile(
            r'\b(?:'
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # 10.x.x.x
            r'192\.168\.\d{1,3}\.\d{1,3}|'      # 192.168.x.x
            r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}'  # 172.16-31.x.x
            r')\b'
        )

        # External/general IP addresses (excluding localhost and private)
        self.external_ip_pattern = re.compile(
            r'\b(?!127\.0\.0\.1\b)(?!10\.\d)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)'
            r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        # Hostnames (common internal patterns)
        self.hostname_pattern = re.compile(
            r'\b(?:[a-zA-Z][a-zA-Z0-9-]*\.)+(?:local|internal|corp|lan|intranet|private)\b',
            re.IGNORECASE
        )

        # UNC paths
        self.unc_path_pattern = re.compile(
            r'\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.$-]+(?:\\[a-zA-Z0-9_.$-]+)*'
        )

        # Passwords in various formats
        self.password_patterns = [
            re.compile(r'(password\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE),
            re.compile(r'(pwd\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE),
            re.compile(r'(passwd\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE),
            re.compile(r'(secret\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE),
            re.compile(r'("password"\s*:\s*")([^"]+)', re.IGNORECASE),
            re.compile(r'("pwd"\s*:\s*")([^"]+)', re.IGNORECASE),
        ]

        # API keys and tokens (common patterns)
        self.api_key_patterns = [
            re.compile(r'(api[_-]?key\s*[=:]\s*)([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
            re.compile(r'(token\s*[=:]\s*)([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
            re.compile(r'(bearer\s+)([a-zA-Z0-9_.-]{20,})', re.IGNORECASE),
            re.compile(r'("api[_-]?key"\s*:\s*")([^"]{20,})', re.IGNORECASE),
            re.compile(r'("token"\s*:\s*")([^"]{20,})', re.IGNORECASE),
            re.compile(r'\b(sk-[a-zA-Z0-9]{20,})\b'),  # OpenAI-style keys
            re.compile(r'\b(pk_[a-zA-Z0-9]{20,})\b'),  # Stripe-style keys
        ]

        # Authorization headers
        self.auth_header_pattern = re.compile(
            r'(Authorization\s*:\s*)(Basic|Bearer|Digest)\s+([^\s\r\n]+)',
            re.IGNORECASE
        )

        # Database connection strings
        self.db_connection_patterns = [
            re.compile(r'(jdbc:[a-zA-Z0-9]+://[^;\s]+)', re.IGNORECASE),
            re.compile(r'((?:Server|Data Source)\s*=\s*)([^;\s]+)', re.IGNORECASE),
            re.compile(r'((?:User ID|uid)\s*=\s*)([^;\s]+)', re.IGNORECASE),
        ]

        # Private keys and certificates
        self.private_key_pattern = re.compile(
            r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----'
        )
        self.certificate_pattern = re.compile(
            r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'
        )

        # MAC addresses
        self.mac_address_pattern = re.compile(
            r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
        )

        # Credit card numbers (basic pattern with Luhn validation done separately)
        self.credit_card_pattern = re.compile(
            r'\b(?:\d{4}[- ]?){3}\d{4}\b'
        )

        # SSN pattern (US format)
        self.ssn_pattern = re.compile(
            r'\b\d{3}-\d{2}-\d{4}\b'
        )

        # Usernames in context
        self.username_patterns = [
            re.compile(r'(user(?:name)?\s*[=:]\s*)([a-zA-Z0-9_@.-]+)', re.IGNORECASE),
            re.compile(r'("user(?:name)?"\s*:\s*")([^"]+)', re.IGNORECASE),
            re.compile(r'(login\s*[=:]\s*)([a-zA-Z0-9_@.-]+)', re.IGNORECASE),
        ]

        # Tableau-specific patterns
        self.site_pattern = re.compile(r'(site\s*[=:]\s*)([a-zA-Z0-9_-]+)', re.IGNORECASE)
        self.workbook_pattern = re.compile(r'(workbook\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE)
        self.datasource_pattern = re.compile(r'(datasource\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE)
        self.project_pattern = re.compile(r'(project\s*[=:]\s*)([^\s,;\'"}\]]+)', re.IGNORECASE)

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    def anonymize_content(self, content: str) -> str:
        """Anonymize all sensitive data in the given content."""

        # Email addresses
        content = self.email_pattern.sub(
            lambda m: self.mapper.get_replacement('email', m.group(0), 'USER_EMAIL') + '@redacted.com',
            content
        )

        # Internal IP addresses
        content = self.internal_ip_pattern.sub(
            lambda m: self.mapper.get_replacement('internal_ip', m.group(0), 'INTERNAL_IP'),
            content
        )

        # External IP addresses
        content = self.external_ip_pattern.sub(
            lambda m: self.mapper.get_replacement('external_ip', m.group(0), 'EXTERNAL_IP'),
            content
        )

        # Hostnames
        content = self.hostname_pattern.sub(
            lambda m: self.mapper.get_replacement('hostname', m.group(0), 'HOST') + '.redacted',
            content
        )

        # UNC paths
        content = self.unc_path_pattern.sub(
            lambda m: '\\\\REDACTED_SERVER\\REDACTED_SHARE',
            content
        )

        # Passwords
        for pattern in self.password_patterns:
            content = pattern.sub(
                lambda m: m.group(1) + 'PASSWORD_REDACTED',
                content
            )

        # API keys and tokens
        for pattern in self.api_key_patterns:
            if pattern.groups == 2:
                content = pattern.sub(
                    lambda m: m.group(1) + 'API_KEY_REDACTED',
                    content
                )
            else:
                content = pattern.sub('API_KEY_REDACTED', content)

        # Authorization headers
        content = self.auth_header_pattern.sub(
            lambda m: m.group(1) + m.group(2) + ' AUTH_TOKEN_REDACTED',
            content
        )

        # Database connection strings
        for pattern in self.db_connection_patterns:
            content = pattern.sub(
                lambda m: m.group(1) + 'DB_CONNECTION_REDACTED' if pattern.groups == 2 else 'DB_CONNECTION_REDACTED',
                content
            )

        # Private keys
        content = self.private_key_pattern.sub('PRIVATE_KEY_REDACTED', content)
        self.mapper.stats['private_key'] += len(self.private_key_pattern.findall(content))

        # Certificates
        content = self.certificate_pattern.sub('CERTIFICATE_REDACTED', content)
        self.mapper.stats['certificate'] += len(self.certificate_pattern.findall(content))

        # MAC addresses
        content = self.mac_address_pattern.sub(
            lambda m: self.mapper.get_replacement('mac_address', m.group(0), 'MAC'),
            content
        )

        # Credit card numbers (with Luhn validation)
        def replace_cc(match):
            cc = match.group(0)
            cc_digits = ''.join(c for c in cc if c.isdigit())
            if self._luhn_check(cc_digits):
                self.mapper.stats['credit_card'] += 1
                return 'CREDIT_CARD_REDACTED'
            return cc
        content = self.credit_card_pattern.sub(replace_cc, content)

        # SSN
        content = self.ssn_pattern.sub(
            lambda m: 'SSN_REDACTED',
            content
        )

        # Usernames
        for pattern in self.username_patterns:
            content = pattern.sub(
                lambda m: m.group(1) + self.mapper.get_replacement('username', m.group(2), 'USER'),
                content
            )

        # Tableau-specific
        content = self.site_pattern.sub(
            lambda m: m.group(1) + self.mapper.get_replacement('site', m.group(2), 'SITE'),
            content
        )
        content = self.workbook_pattern.sub(
            lambda m: m.group(1) + self.mapper.get_replacement('workbook', m.group(2), 'WORKBOOK'),
            content
        )
        content = self.datasource_pattern.sub(
            lambda m: m.group(1) + self.mapper.get_replacement('datasource', m.group(2), 'DATASOURCE'),
            content
        )
        content = self.project_pattern.sub(
            lambda m: m.group(1) + self.mapper.get_replacement('project', m.group(2), 'PROJECT'),
            content
        )

        return content

    def should_process_file(self, filepath: Path) -> bool:
        """Check if a file should be processed based on its extension."""
        return filepath.suffix.lower() in self.TEXT_EXTENSIONS

    def process_file(self, filepath: Path) -> bool:
        """Process a single file, anonymizing its contents. Returns True if successful."""
        try:
            # Try to read as text with various encodings
            content = None
            for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
                try:
                    with open(filepath, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue

            if content is None:
                print(f"  Warning: Could not decode {filepath.name}, skipping")
                return True  # Not a failure, just can't process

            # Anonymize content
            anonymized = self.anonymize_content(content)

            # Write back
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(anonymized)

            return True

        except Exception as e:
            print(f"  Error processing {filepath}: {e}")
            return False


def process_zip(zip_path: str) -> bool:
    """
    Main processing function.
    Extracts zip, anonymizes all files, creates anonymized zip.
    Returns True on success, False on failure.
    """
    zip_path = Path(zip_path)

    if not zip_path.exists():
        print(f"Error: File not found: {zip_path}")
        return False

    if not zipfile.is_zipfile(zip_path):
        print(f"Error: Not a valid zip file: {zip_path}")
        return False

    # Create output directory name
    output_dir = zip_path.parent / (zip_path.stem + "_anonymized")
    output_zip = zip_path.parent / (zip_path.stem + "_anonymized.zip")

    # Clean up any existing output
    if output_dir.exists():
        shutil.rmtree(output_dir)
    if output_zip.exists():
        output_zip.unlink()

    anonymizer = LogAnonymizer()

    try:
        # Extract zip
        print(f"Extracting {zip_path.name}...")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(output_dir)

        # Get all files to process
        all_files = list(output_dir.rglob('*'))
        text_files = [f for f in all_files if f.is_file() and anonymizer.should_process_file(f)]

        print(f"Found {len(text_files)} text files to anonymize...")

        # Process each file
        processed = 0
        failed = 0
        for filepath in text_files:
            relative = filepath.relative_to(output_dir)
            if anonymizer.process_file(filepath):
                processed += 1
            else:
                failed += 1

            # Progress update every 50 files
            if processed % 50 == 0:
                print(f"  Processed {processed}/{len(text_files)} files...")

        if failed > 0:
            raise Exception(f"{failed} files failed to process")

        print(f"Processed {processed} files successfully")

        # Create anonymized zip
        print(f"Creating anonymized zip: {output_zip.name}...")
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filepath in output_dir.rglob('*'):
                if filepath.is_file():
                    arcname = filepath.relative_to(output_dir)
                    zf.write(filepath, arcname)

        # Clean up extracted directory
        shutil.rmtree(output_dir)

        # Print statistics
        print("\n" + "="*60)
        print("ANONYMIZATION COMPLETE")
        print("="*60)
        print(f"\nOutput file: {output_zip}")
        print(f"\nReplacement Statistics (total occurrences):")

        stats = anonymizer.mapper.get_stats()
        unique = anonymizer.mapper.get_unique_counts()

        for category in sorted(stats.keys()):
            total = stats[category]
            uniq = unique.get(category, 0)
            print(f"  {category}: {total} replacements ({uniq} unique values)")

        if not stats:
            print("  No sensitive data patterns were found.")

        print("\n" + "="*60)

        return True

    except Exception as e:
        print(f"\nError during processing: {e}")
        print("Cleaning up...")

        # Clean up on failure
        if output_dir.exists():
            shutil.rmtree(output_dir)
        if output_zip.exists():
            output_zip.unlink()

        return False


def main():
    parser = argparse.ArgumentParser(
        description='Anonymize sensitive data in log archives for safe sharing with LLMs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python anonymizer.py ziplogs.zip
  python anonymizer.py "path/to/logs archive.zip"
        '''
    )
    parser.add_argument('zipfile', help='Path to the zip file containing logs')

    args = parser.parse_args()

    success = process_zip(args.zipfile)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
