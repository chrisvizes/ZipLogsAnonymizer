#!/usr/bin/env python3
"""
Pattern definitions for sensitive data detection and anonymization.

Patterns are defined here as Python dataclasses (source of truth).
Actual matching is performed by the Rust core (anonymizer_core) using
Aho-Corasick keyword pre-filtering and compiled regex.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

# Import Rust core for high-performance processing (required at point of use).
# Soft-fail at import time so auto-build has a chance to run first.
_rust_core_available = False
_rust_import_error = None

try:
    from anonymizer_core import AnonymizerCore, is_rust_core_available as _is_rust_available
    if _is_rust_available():
        _rust_core_available = True
    else:
        _rust_import_error = "Rust core reports unavailable"
except ImportError as e:
    _rust_import_error = str(e)
    AnonymizerCore = None

    def _is_rust_available():
        return False


def check_rust_core():
    """Raise ImportError if the Rust core is not available.
    Called at the point of actual use, not at import time.
    """
    if not _rust_core_available:
        raise ImportError(
            "Rust anonymization core (anonymizer_core) is required but not found. "
            "Please build the Rust extension with: cd rust_core && maturin develop --release\n"
            f"Original error: {_rust_import_error}"
        )


def reload_rust_core():
    """Re-attempt importing the Rust core (after auto-build)."""
    global _rust_core_available, _rust_import_error, AnonymizerCore
    try:
        import importlib
        mod = importlib.import_module('anonymizer_core')
        AnonymizerCore = mod.AnonymizerCore
        if mod.is_rust_core_available():
            _rust_core_available = True
            _rust_import_error = None
        else:
            _rust_import_error = "Rust core reports unavailable after reload"
    except ImportError as e:
        _rust_import_error = str(e)


@dataclass
class PatternConfig:
    """Configuration for a single pattern."""

    name: str
    pattern: re.Pattern
    replacement: str
    uses_groups: bool
    # Literal keywords that MUST appear for this pattern to match (LOWERCASE)
    required_keywords: frozenset[str]
    # Whether this pattern can span multiple lines
    multiline: bool = False


class PatternMatcher:
    """
    Pattern definitions for sensitive data detection.

    Pattern definitions live here as the source of truth. Actual matching
    is performed by the Rust core (anonymizer_core) using Aho-Corasick
    keyword pre-filtering and compiled regex for 5-15x faster processing.
    """

    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> list[PatternConfig]:
        """
        Compile patterns with optimization flags.
        All keywords are PRE-LOWERCASED for faster matching.
        """
        patterns = []

        # === HIGH SPECIFICITY PATTERNS (match rare, specific structures) ===

        # Private keys - very specific BEGIN/END markers (MULTILINE)
        patterns.append(
            PatternConfig(
                name="private_key",
                pattern=re.compile(
                    r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----"
                ),
                replacement="PRIVATE_KEY_REDACTED",
                uses_groups=False,
                required_keywords=frozenset(["-----begin"]),  # lowercase
                multiline=True,
            )
        )

        # Certificates (MULTILINE)
        patterns.append(
            PatternConfig(
                name="certificate",
                pattern=re.compile(
                    r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
                ),
                replacement="CERTIFICATE_REDACTED",
                uses_groups=False,
                required_keywords=frozenset(["-----begin certificate"]),  # lowercase
                multiline=True,
            )
        )

        # SQL queries - redact entire query to prevent leaking sensitive
        # data in column names, string literals, and table references (MULTILINE)
        patterns.append(
            PatternConfig(
                name="sql_query",
                pattern=re.compile(
                    r'^[ \t]*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE(?:\s+FROM)?|WITH)\b'
                    r'[^\n]*'
                    r'(?:\n(?:[ \t]+\S[^\n]*|[)][^\n]*|(?:SELECT|FROM|WHERE|GROUP\s+BY'
                    r'|ORDER\s+BY|HAVING|LIMIT|OFFSET|UNION|INTERSECT|EXCEPT|AND|OR'
                    r'|SET|VALUES|INTO|CASE|WHEN|THEN|ELSE|END|JOIN|LEFT|RIGHT|INNER'
                    r'|OUTER|CROSS|FULL|NATURAL|ON|AS)\b[^\n]*))*',
                    re.IGNORECASE | re.MULTILINE,
                ),
                replacement="QUERY_REDACTED",
                uses_groups=False,
                required_keywords=frozenset(
                    ["select ", "insert into", "update ", "delete "]
                ),
                multiline=True,
            )
        )

        # Authorization headers - specific prefix
        patterns.append(
            PatternConfig(
                name="auth_header",
                pattern=re.compile(
                    r"(Authorization\s*:\s*(?:Basic|Bearer|Digest)\s+)\S+",
                    re.IGNORECASE,
                ),
                replacement=r"\1AUTH_TOKEN_REDACTED",
                uses_groups=True,
                required_keywords=frozenset(["authorization"]),
            )
        )

        # JDBC connection strings - specific prefix
        patterns.append(
            PatternConfig(
                name="db_connection",
                pattern=re.compile(r'jdbc:[a-zA-Z0-9]+://[^;\s"]+'),
                replacement="DB_REDACTED",
                uses_groups=False,
                required_keywords=frozenset(["jdbc:"]),
            )
        )

        # UNC paths - specific \\ prefix
        patterns.append(
            PatternConfig(
                name="unc_path",
                pattern=re.compile(
                    r"\\{2,}[a-zA-Z0-9_.-]+\\{1,}[a-zA-Z0-9_.$-]+(?:\\{1,}[a-zA-Z0-9_.$-]+)*"
                ),
                replacement=r"\\\\REDACTED_SERVER\\\\REDACTED_SHARE",
                uses_groups=False,
                required_keywords=frozenset(["\\\\"]),
            )
        )

        # SSN - specific format
        patterns.append(
            PatternConfig(
                name="ssn",
                pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                replacement="SSN_REDACTED",
                uses_groups=False,
                required_keywords=frozenset(["-"]),
            )
        )

        # MAC addresses - specific format with colons or dashes
        patterns.append(
            PatternConfig(
                name="mac_address",
                pattern=re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
                replacement="MAC_REDACTED",
                uses_groups=False,
                required_keywords=frozenset([":", "-"]),
            )
        )

        # === MEDIUM SPECIFICITY PATTERNS ===

        # Email addresses - requires @
        patterns.append(
            PatternConfig(
                name="email",
                pattern=re.compile(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                    re.IGNORECASE,
                ),
                replacement="{UNIQUE}@redacted.com",
                uses_groups=False,
                required_keywords=frozenset(["@"]),
            )
        )

        # Internal IP addresses - optimized with non-capturing groups
        patterns.append(
            PatternConfig(
                name="internal_ip",
                pattern=re.compile(
                    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                    r"192\.168\.\d{1,3}\.\d{1,3}|"
                    r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b"
                ),
                replacement="{UNIQUE}",
                uses_groups=False,
                required_keywords=frozenset(["10.", "192.", "172."]),
            )
        )

        # Hostnames with internal TLDs
        patterns.append(
            PatternConfig(
                name="hostname",
                pattern=re.compile(
                    r"\b(?:[a-zA-Z][a-zA-Z0-9-]*\.)+(?:local|internal|corp|lan|intranet|private)\b",
                    re.IGNORECASE,
                ),
                replacement="{UNIQUE}.redacted",
                uses_groups=False,
                required_keywords=frozenset(
                    [".local", ".internal", ".corp", ".lan", ".intranet", ".private"]
                ),
            )
        )

        # === CONTEXT-DEPENDENT PATTERNS (require keyword prefix) ===

        # Passwords with context
        patterns.append(
            PatternConfig(
                name="password",
                pattern=re.compile(
                    r'((?:password|passwd|pwd|secret)\s*[=:]\s*)[^\s,;\\\'"}\]]+|'
                    r'("(?:password|passwd|pwd|secret)"\s*:\s*")[^"]+',
                    re.IGNORECASE,
                ),
                replacement=r"\1PASSWORD_REDACTED",
                uses_groups=True,
                required_keywords=frozenset(["password", "passwd", "pwd", "secret"]),
            )
        )

        # API keys with context
        patterns.append(
            PatternConfig(
                name="api_key",
                pattern=re.compile(
                    r"((?:api[_-]?key|token|bearer)\s*[=:]\s*)[a-zA-Z0-9_-]{20,}|"
                    r'("(?:api[_-]?key|token)"\s*:\s*")[^"]{20,}',
                    re.IGNORECASE,
                ),
                replacement=r"\1API_KEY_REDACTED",
                uses_groups=True,
                required_keywords=frozenset(
                    ["api_key", "api-key", "apikey", "token", "bearer"]
                ),
            )
        )

        # Database connection params
        patterns.append(
            PatternConfig(
                name="db_connection",
                pattern=re.compile(
                    r'\b(?:Server|Data Source|User ID|uid)\s*=\s*[^;\s"]+',
                    re.IGNORECASE,
                ),
                replacement="DB_REDACTED",
                uses_groups=False,
                required_keywords=frozenset(
                    ["server=", "data source=", "user id=", "uid="]
                ),
            )
        )

        # Usernames with context
        patterns.append(
            PatternConfig(
                name="username",
                pattern=re.compile(
                    r"((?:user(?:name)?|login)\s*[=:]\s*)([a-zA-Z0-9_@.-]+)|"
                    r'("(?:user(?:name)?|login)"\s*:\s*")([^"]+)',
                    re.IGNORECASE,
                ),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["user=", "user:", "username", "login", '"user"']),
            )
        )

        # Tableau URL path patterns - content names in URL paths
        # These must be defined BEFORE the key=value tableau_entity pattern
        # so they get lower indices and are applied first.

        # Site name from /t/SITE_NAME/...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/t/)([^/]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/t/"]),
            )
        )

        # VizQL workbook from /vizql/w/WORKBOOK/...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/vizql/w/)([^/]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/vizql/"]),
            )
        )

        # VizQL view from /vizql/w/.../v/VIEW/...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/vizql/w/[^/]+/v/)([^/]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/vizql/"]),
            )
        )

        # Views workbook from /views/WORKBOOK/...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/views/)([^/]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/views/"]),
            )
        )

        # Views view from /views/.../VIEW?...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/views/[^/]+/)([^/?#\s]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/views/"]),
            )
        )

        # Authoring workbook from /authoring/WORKBOOK/...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/authoring/)([^/]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/authoring/"]),
            )
        )

        # Authoring view from /authoring/.../VIEW?...
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(r'(/authoring/[^/]+/)([^/?#\s]+)'),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(["/authoring/"]),
            )
        )

        # Tableau-specific entities (key=value and JSON contexts)
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(
                    r'((?:site|workbook|datasource|project|vw|wb)\s*[=:]\s*)([^\s,;\\\'"}\]]+)|'
                    r'("(?:site|workbook|datasource|project|vw|wb)"\s*:\s*")([^"]+)',
                    re.IGNORECASE,
                ),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(
                    ["site=", "site:", "workbook", "datasource", "project",
                     '"site"', '"vw"', '"wb"', "vw=", "vw:", "wb=", "wb:"]
                ),
            )
        )

        return patterns

class FastAnonymizer:
    """
    High-performance anonymizer using Rust acceleration.

    Uses the Rust core (anonymizer_core) for 5-15x faster processing compared
    to pure Python regex. Rust core is required.
    """

    def __init__(self, matcher: PatternMatcher):
        check_rust_core()
        self.matcher = matcher
        self.counts: dict[str, int] = defaultdict(int)
        self.unique_counters: dict[str, dict[str, int]] = defaultdict(dict)
        self._rust_core = AnonymizerCore()

    def reset(self):
        """Reset counters for a new file."""
        self.counts = defaultdict(int)
        self.unique_counters = defaultdict(dict)
        # Reset Rust core if available
        if self._rust_core is not None:
            try:
                self._rust_core.reset()
            except Exception:
                pass

    def process_content(self, content: str, full_reset: bool = True) -> tuple[str, dict[str, int]]:
        """Process content using high-performance Rust engine.

        Args:
            content: The text content to anonymize
            full_reset: If True, reset all counters. If False, preserve unique_counters
                       for consistency across chunks.

        Returns:
            Tuple of (anonymized_content, category_counts)
        """
        if full_reset:
            self.reset()
        else:
            # Reset counts only, preserve unique_counters for consistency across chunks
            self.counts = defaultdict(int)

        result, rust_counts = self._rust_core.process_content(content)
        for k, v in rust_counts.items():
            self.counts[k] += v
        return result, dict(self.counts)


# Module-level fast anonymizer cache (one per process)
_fast_anonymizer: Optional[FastAnonymizer] = None


def get_fast_anonymizer(matcher: PatternMatcher) -> FastAnonymizer:
    """Get or create the fast anonymizer instance."""
    global _fast_anonymizer
    if _fast_anonymizer is None:
        _fast_anonymizer = FastAnonymizer(matcher)
    return _fast_anonymizer


def anonymize_content(
    content: str, matcher: PatternMatcher
) -> tuple[str, dict[str, int]]:
    """
    Anonymize content using optimized FastAnonymizer.
    """
    anonymizer = get_fast_anonymizer(matcher)
    return anonymizer.process_content(content)


def anonymize_content_hybrid(
    content: str, matcher: PatternMatcher
) -> tuple[str, dict[str, int]]:
    """
    Hybrid approach: use standard for small content, chunked for large.
    """
    LINE_THRESHOLD = 10000
    line_count = content.count("\n")

    if line_count < LINE_THRESHOLD:
        return anonymize_content(content, matcher)
    else:
        return anonymize_content_chunked(content, matcher)


def anonymize_content_chunked(
    content: str, matcher: PatternMatcher, chunk_size: int = 100000
) -> tuple[str, dict[str, int]]:
    """
    Process very large content in chunks to maintain cache efficiency.
    Increased chunk size from 50k to 100k for better throughput.
    """
    if len(content) <= chunk_size:
        return anonymize_content(content, matcher)

    anonymizer = get_fast_anonymizer(matcher)
    # Full reset once at the start so unique_counters persist across chunks
    anonymizer.reset()

    counts: dict[str, int] = defaultdict(int)
    result_parts = []

    # Split into chunks at line boundaries
    lines = content.split("\n")
    current_chunk = []
    current_size = 0

    for line in lines:
        current_chunk.append(line)
        current_size += len(line) + 1

        if current_size >= chunk_size:
            chunk_content = "\n".join(current_chunk)
            chunk_result, chunk_counts = anonymizer.process_content(chunk_content, full_reset=False)
            result_parts.append(chunk_result)

            for cat, count in chunk_counts.items():
                counts[cat] += count

            current_chunk = []
            current_size = 0

    # Process remaining
    if current_chunk:
        chunk_content = "\n".join(current_chunk)
        chunk_result, chunk_counts = anonymizer.process_content(chunk_content, full_reset=False)
        result_parts.append(chunk_result)

        for cat, count in chunk_counts.items():
            counts[cat] += count

    return "\n".join(result_parts), dict(counts)
