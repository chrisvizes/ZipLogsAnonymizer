#!/usr/bin/env python3
"""
Pattern matching for sensitive data detection and anonymization.

OPTIMIZED VERSION - Key techniques:
1. Pre-computed lowercase keywords with O(1) set lookups
2. Single-pass keyword detection using set intersection
3. Cached replacer functions (no function creation in hot loops)
4. Use subn() instead of findall() + sub() to avoid double work
5. Minimized string allocations and .lower() calls
6. Batch line processing to reduce Python loop overhead
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Callable


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
    # Pre-computed: keywords as a set for fast intersection
    _keywords_set: set = field(default_factory=set, repr=False)

    def __post_init__(self):
        self._keywords_set = set(self.required_keywords)


class PatternMatcher:
    """
    High-performance pattern matcher using multiple optimization strategies.

    Optimizations:
    - All keywords pre-lowercased at compile time
    - Single set of all keywords for fast pre-filtering
    - Keyword-to-pattern index for O(1) pattern lookup
    - Replacer functions pre-created (not in hot loop)
    """

    def __init__(self):
        self.patterns = self._compile_patterns()
        # Pre-compute all keywords for fast content pre-filtering
        self._all_keywords_lower = self._build_keyword_set()
        # Build keyword -> patterns index for fast lookup
        self._keyword_to_patterns = self._build_keyword_index()
        # Pre-compute single-line patterns list
        self._single_line_patterns = [p for p in self.patterns if not p.multiline]
        self._multiline_patterns = [p for p in self.patterns if p.multiline]

    def _build_keyword_set(self) -> frozenset[str]:
        """Build unified lowercase keyword set for pre-filtering."""
        keywords = set()
        for config in self.patterns:
            keywords.update(config.required_keywords)
        return frozenset(keywords)

    def _build_keyword_index(self) -> dict[str, list[PatternConfig]]:
        """Build index from keyword -> list of patterns that use it."""
        index = defaultdict(list)
        for config in self.patterns:
            for keyword in config.required_keywords:
                index[keyword].append(config)
        return dict(index)

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
                required_keywords=frozenset(["user=", "user:", "username", "login", '"user"']),
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
                    ["site=", "site:", "workbook", "datasource", "project"]
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

    def get_applicable_patterns_fast(self, line_lower: str) -> list[PatternConfig]:
        """
        Return patterns whose required keywords appear in the line.
        Expects pre-lowercased line to avoid redundant .lower() calls.
        """
        seen = set()
        applicable = []
        for keyword in self._all_keywords_lower:
            if keyword in line_lower:
                for pattern in self._keyword_to_patterns.get(keyword, []):
                    if id(pattern) not in seen:
                        seen.add(id(pattern))
                        applicable.append(pattern)
        return applicable

    def get_applicable_patterns(self, line: str) -> list[PatternConfig]:
        """
        Return only patterns whose required keywords appear in the line.
        This dramatically reduces regex executions.
        """
        return self.get_applicable_patterns_fast(line.lower())


class FastAnonymizer:
    """
    Optimized anonymizer with pre-created replacer functions and batch processing.
    """

    def __init__(self, matcher: PatternMatcher):
        self.matcher = matcher
        self.counts: dict[str, int] = defaultdict(int)
        self.unique_counters: dict[str, dict[str, int]] = defaultdict(dict)

    def reset(self):
        """Reset counters for a new file."""
        self.counts = defaultdict(int)
        self.unique_counters = defaultdict(dict)

    def get_unique_replacement(self, category: str, original: str, template: str) -> str:
        """Get consistent unique replacement for a value."""
        if original not in self.unique_counters[category]:
            self.unique_counters[category][original] = len(self.unique_counters[category]) + 1
        idx = self.unique_counters[category][original]
        return template.replace("{UNIQUE}", f"{category.upper()}_{idx:03d}")

    def apply_pattern(self, config: PatternConfig, text: str) -> str:
        """Apply a single pattern to text, tracking counts."""
        if "{UNIQUE}" in config.replacement:
            # Need custom replacer for unique values
            def replacer(m):
                original = m.group(0)
                self.counts[config.name] += 1
                if config.uses_groups and m.lastindex:
                    prefix = m.group(1) or ""
                    return prefix + self.get_unique_replacement(
                        config.name, original, config.replacement.replace(r"\1", "")
                    )
                return self.get_unique_replacement(config.name, original, config.replacement)
            return config.pattern.sub(replacer, text)

        elif config.uses_groups:
            def replacer(m):
                self.counts[config.name] += 1
                result = config.replacement
                for i in range(1, (m.lastindex or 0) + 1):
                    grp = m.group(i)
                    if grp:
                        result = result.replace(f"\\{i}", grp)
                        break
                return result
            return config.pattern.sub(replacer, text)

        else:
            # Simple replacement - use subn for count + replace in one pass
            new_text, count = config.pattern.subn(config.replacement, text)
            if count:
                self.counts[config.name] += count
            return new_text

    def process_content(self, content: str) -> tuple[str, dict[str, int]]:
        """Process content with all optimizations."""
        self.reset()

        # Fast path: skip content with no potential matches
        if not self.matcher.content_may_have_matches(content):
            return content, {}

        # PHASE 1: Apply multiline patterns to full content
        for config in self.matcher._multiline_patterns:
            content_lower = content.lower()
            if any(kw in content_lower for kw in config.required_keywords):
                content = self.apply_pattern(config, content)

        # PHASE 2: Batch line processing for single-line patterns
        # Process in batches to reduce loop overhead
        lines = content.split("\n")
        result_lines = []

        # Pre-fetch pattern list to avoid attribute lookup in loop
        single_patterns = self.matcher._single_line_patterns
        all_keywords = self.matcher._all_keywords_lower
        keyword_to_patterns = self.matcher._keyword_to_patterns

        for line in lines:
            if not line:
                result_lines.append(line)
                continue

            # Single .lower() call per line
            line_lower = line.lower()

            # Fast keyword check - find which keywords are present
            present_keywords = [kw for kw in all_keywords if kw in line_lower]

            if not present_keywords:
                result_lines.append(line)
                continue

            # Get unique applicable patterns
            seen_patterns = set()
            applicable = []
            for kw in present_keywords:
                for pattern in keyword_to_patterns.get(kw, []):
                    if not pattern.multiline and id(pattern) not in seen_patterns:
                        seen_patterns.add(id(pattern))
                        applicable.append(pattern)

            if not applicable:
                result_lines.append(line)
                continue

            # Apply patterns to line
            modified = line
            for config in applicable:
                modified = self.apply_pattern(config, modified)

            result_lines.append(modified)

        return "\n".join(result_lines), dict(self.counts)


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
            chunk_result, chunk_counts = anonymize_content(chunk_content, matcher)
            result_parts.append(chunk_result)

            for cat, count in chunk_counts.items():
                counts[cat] += count

            current_chunk = []
            current_size = 0

    # Process remaining
    if current_chunk:
        chunk_content = "\n".join(current_chunk)
        chunk_result, chunk_counts = anonymize_content(chunk_content, matcher)
        result_parts.append(chunk_result)

        for cat, count in chunk_counts.items():
            counts[cat] += count

    return "\n".join(result_parts), dict(counts)
