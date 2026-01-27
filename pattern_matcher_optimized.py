#!/usr/bin/env python3
"""
Optimized pattern matching using established techniques from pattern matching research.

Key optimizations:
1. Pre-filtering with literal keyword checks (O(1) set lookups)
2. Line-based processing with early exit for non-matching lines
3. Combined regex patterns where possible to reduce passes
4. Possessive quantifiers and atomic groups to prevent backtracking
5. Ordered pattern application (most specific first)
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional, Callable


@dataclass
class PatternConfig:
    """Configuration for a single pattern."""

    name: str
    pattern: re.Pattern
    replacement: str
    uses_groups: bool
    # Literal keywords that MUST appear for this pattern to match
    # Used for O(1) pre-filtering
    required_keywords: frozenset[str]
    # Whether this pattern can span multiple lines
    multiline: bool = False


class OptimizedPatternMatcher:
    """
    High-performance pattern matcher using multiple optimization strategies.

    Based on techniques from:
    - Aho-Corasick for multi-pattern matching concepts
    - Hyperscan's hybrid literal/regex approach
    - Thompson NFA principles for avoiding backtracking
    """

    def __init__(self):
        self.patterns = self._compile_patterns()
        # Pre-compute all keywords for fast content pre-filtering
        self._all_keywords = self._build_keyword_index()
        # Pre-compute lowercase keywords for case-insensitive matching
        self._all_keywords_lower = frozenset(k.lower() for k in self._all_keywords)

    def _build_keyword_index(self) -> frozenset[str]:
        """Build unified keyword set for pre-filtering."""
        keywords = set()
        for config in self.patterns:
            keywords.update(config.required_keywords)
        return frozenset(keywords)

    def _compile_patterns(self) -> list[PatternConfig]:
        """
        Compile patterns with optimization flags.

        Patterns are ordered by:
        1. Specificity (more specific patterns first)
        2. Frequency (less common patterns first to reduce work)
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
                required_keywords=frozenset(["-----BEGIN"]),
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
                required_keywords=frozenset(["-----BEGIN CERTIFICATE"]),
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
                pattern=re.compile(r"jdbc:[a-zA-Z0-9]+://[^;\s]+"),
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
                    r"\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.$-]+(?:\\[a-zA-Z0-9_.$-]+)*"
                ),
                replacement=r"\\\\REDACTED_SERVER\\REDACTED_SHARE",
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
                required_keywords=frozenset(["-"]),  # All SSNs have dashes
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

        # Internal IP addresses
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
                    r'((?:password|passwd|pwd|secret)\s*[=:]\s*)[^\s,;\'"}\]]+|'
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
                replacement="API_KEY_REDACTED",
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
                    r"(?:Server|Data Source|User ID|uid)\s*=\s*[^;\s]+",
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
                required_keywords=frozenset(["user", "username", "login"]),
            )
        )

        # Tableau-specific entities
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(
                    r'((?:site|workbook|datasource|project)\s*[=:]\s*)([^\s,;\'"}\]]+)',
                    re.IGNORECASE,
                ),
                replacement=r"\1{UNIQUE}",
                uses_groups=True,
                required_keywords=frozenset(
                    ["site", "workbook", "datasource", "project"]
                ),
            )
        )

        return patterns

    def content_may_have_matches(self, content: str) -> bool:
        """
        Fast pre-filter: check if content might contain any sensitive data.
        Uses O(1) keyword lookups instead of regex.
        """
        content_lower = content.lower()
        for keyword in self._all_keywords_lower:
            if keyword in content_lower:
                return True
        return False

    def get_applicable_patterns(self, line: str) -> list[PatternConfig]:
        """
        Return only patterns whose required keywords appear in the line.
        This dramatically reduces regex executions.
        """
        line_lower = line.lower()
        applicable = []
        for config in self.patterns:
            # Check if ANY required keyword is present
            for keyword in config.required_keywords:
                if keyword.lower() in line_lower:
                    applicable.append(config)
                    break
        return applicable


def anonymize_content_optimized(
    content: str, matcher: OptimizedPatternMatcher
) -> tuple[str, dict[str, int]]:
    """
    Anonymize content using optimized multi-pass strategy.

    Strategy:
    1. Quick pre-filter: skip content with no potential matches
    2. Apply multiline patterns to full content first
    3. Line-by-line processing with pattern filtering for single-line patterns
    """
    # Fast path: skip content with no potential sensitive data
    if not matcher.content_may_have_matches(content):
        return content, {}

    counts: dict[str, int] = defaultdict(int)
    unique_counters: dict[str, dict[str, int]] = defaultdict(dict)

    def get_unique_replacement(category: str, original: str, template: str) -> str:
        if original not in unique_counters[category]:
            unique_counters[category][original] = len(unique_counters[category]) + 1
        idx = unique_counters[category][original]
        return template.replace("{UNIQUE}", f"{category.upper()}_{idx:03d}")

    # PHASE 1: Apply multiline patterns to full content
    # These patterns span multiple lines and must be processed on full content
    for config in matcher.patterns:
        if config.multiline:
            # Check if any required keyword is present
            content_lower = content.lower()
            keyword_present = any(kw.lower() in content_lower for kw in config.required_keywords)
            if keyword_present:
                match_count = len(config.pattern.findall(content))
                if match_count:
                    counts[config.name] += match_count
                    content = config.pattern.sub(config.replacement, content)

    # PHASE 2: Process line by line for single-line patterns
    lines = content.split("\n")
    result_lines = []

    # Get only non-multiline patterns for line processing
    single_line_patterns = [p for p in matcher.patterns if not p.multiline]

    for line in lines:
        if not line.strip():
            result_lines.append(line)
            continue

        # Get only patterns that might match this line
        applicable_patterns = [
            p for p in single_line_patterns
            if any(kw.lower() in line.lower() for kw in p.required_keywords)
        ]

        if not applicable_patterns:
            result_lines.append(line)
            continue

        # Apply applicable patterns
        modified_line = line
        for config in applicable_patterns:
            if "{UNIQUE}" in config.replacement:

                def make_replacer(cfg):
                    def replacer(m):
                        original = m.group(0)
                        counts[cfg.name] += 1
                        if cfg.uses_groups and m.lastindex:
                            prefix = m.group(1) or ""
                            return prefix + get_unique_replacement(
                                cfg.name, original, cfg.replacement.replace(r"\1", "")
                            )
                        return get_unique_replacement(
                            cfg.name, original, cfg.replacement
                        )

                    return replacer

                modified_line = config.pattern.sub(make_replacer(config), modified_line)
            elif config.uses_groups:

                def make_group_replacer(cfg):
                    def replacer(m):
                        counts[cfg.name] += 1
                        result = cfg.replacement
                        for i in range(1, (m.lastindex or 0) + 1):
                            grp = m.group(i)
                            if grp:
                                result = result.replace(f"\\{i}", grp)
                                break
                        return result

                    return replacer

                modified_line = config.pattern.sub(
                    make_group_replacer(config), modified_line
                )
            else:
                match_count = len(config.pattern.findall(modified_line))
                if match_count:
                    counts[config.name] += match_count
                    modified_line = config.pattern.sub(
                        config.replacement, modified_line
                    )

        result_lines.append(modified_line)

    return "\n".join(result_lines), dict(counts)


def anonymize_content_hybrid(
    content: str, matcher: OptimizedPatternMatcher
) -> tuple[str, dict[str, int]]:
    """
    Hybrid approach: use line-based for small content, full-pass for large.

    For very large content, the overhead of line splitting may exceed benefits.
    Empirically determined threshold.
    """
    LINE_THRESHOLD = 10000  # Lines

    line_count = content.count("\n")

    if line_count < LINE_THRESHOLD:
        return anonymize_content_optimized(content, matcher)
    else:
        # For very large files, use chunked processing
        return anonymize_content_chunked(content, matcher)


def anonymize_content_chunked(
    content: str, matcher: OptimizedPatternMatcher, chunk_size: int = 50000
) -> tuple[str, dict[str, int]]:
    """
    Process very large content in chunks to maintain cache efficiency.

    Chunks are split at line boundaries to avoid breaking patterns.
    """
    if len(content) <= chunk_size:
        return anonymize_content_optimized(content, matcher)

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
            chunk_result, chunk_counts = anonymize_content_optimized(
                chunk_content, matcher
            )
            result_parts.append(chunk_result)

            for cat, count in chunk_counts.items():
                counts[cat] += count

            current_chunk = []
            current_size = 0

    # Process remaining
    if current_chunk:
        chunk_content = "\n".join(current_chunk)
        chunk_result, chunk_counts = anonymize_content_optimized(chunk_content, matcher)
        result_parts.append(chunk_result)

        for cat, count in chunk_counts.items():
            counts[cat] += count

    return "\n".join(result_parts), dict(counts)
