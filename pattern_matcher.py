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
7. Optional Rust acceleration via PyO3 (5-15x faster when available)
"""

import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Callable

# Try to import Rust core for high-performance processing
# Falls back to pure Python if not available
FORCE_PYTHON_MODE = os.environ.get('ANONYMIZER_FORCE_PYTHON', '').lower() in ('1', 'true', 'yes')

if FORCE_PYTHON_MODE:
    RUST_CORE_AVAILABLE = False
    AnonymizerCore = None
else:
    try:
        from anonymizer_core import AnonymizerCore, is_rust_core_available
        RUST_CORE_AVAILABLE = is_rust_core_available()
    except ImportError:
        RUST_CORE_AVAILABLE = False
        AnonymizerCore = None


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

        # Tableau-specific entities
        patterns.append(
            PatternConfig(
                name="tableau_entity",
                pattern=re.compile(
                    r'((?:site|workbook|datasource|project)\s*[=:]\s*)([^\s,;\\\'"}\]]+)',
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
    Optimized anonymizer with optional Rust acceleration.

    When the Rust core (anonymizer_core) is available, processing is 5-15x faster.
    Falls back to pure Python implementation seamlessly when Rust is not available.

    Set environment variable ANONYMIZER_FORCE_PYTHON=1 to force Python mode.
    """

    def __init__(self, matcher: PatternMatcher):
        self.matcher = matcher
        self.counts: dict[str, int] = defaultdict(int)
        self.unique_counters: dict[str, dict[str, int]] = defaultdict(dict)

        # Initialize Rust core if available
        self._rust_core = None
        if RUST_CORE_AVAILABLE and AnonymizerCore is not None:
            try:
                self._rust_core = AnonymizerCore()
            except Exception:
                # Rust core failed to initialize, fall back to Python
                self._rust_core = None

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

    # Map categories to natural-looking replacement formats
    # These formats are designed to be compatible with tools like LogShark
    # that expect valid-looking usernames, hostnames, etc.
    REPLACEMENT_FORMATS = {
        "username": "user{idx:03d}",          # user001, user002 - looks like a real username
        "email": "user{idx:03d}",             # user001@redacted.com - looks like real email
        "hostname": "host{idx:03d}",          # host001.redacted - looks like real hostname
        "internal_ip": "10.{idx}.0.1",        # 10.1.0.1, 10.2.0.1 - valid internal IP, unlikely to collide
        "tableau_entity": "entity{idx:03d}",  # entity001 - generic entity name
    }

    def get_unique_replacement(self, category: str, original: str, template: str) -> str:
        """Get consistent unique replacement for a value.

        Uses natural-looking formats that are compatible with log analysis tools.
        Same original value always maps to the same replacement.
        """
        if original not in self.unique_counters[category]:
            self.unique_counters[category][original] = len(self.unique_counters[category]) + 1
        idx = self.unique_counters[category][original]

        # Use natural-looking format if available, otherwise fall back to default
        if category in self.REPLACEMENT_FORMATS:
            replacement = self.REPLACEMENT_FORMATS[category].format(idx=idx)
            return template.replace("{UNIQUE}", replacement)
        else:
            return template.replace("{UNIQUE}", f"{category.upper()}_{idx:03d}")

    def apply_pattern(self, config: PatternConfig, text: str) -> str:
        """Apply a single pattern to text, tracking counts."""
        if "{UNIQUE}" in config.replacement:
            # Need custom replacer for unique values
            def replacer(m):
                original = m.group(0)
                self.counts[config.name] += 1
                if config.uses_groups and m.lastindex:
                    # Find the first non-None group (handles alternation patterns
                    # where different alternatives use different group numbers)
                    prefix = ""
                    for i in range(1, m.lastindex + 1):
                        grp = m.group(i)
                        if grp is not None:
                            prefix = grp
                            break
                    return prefix + self.get_unique_replacement(
                        config.name, original, config.replacement.replace(r"\1", "")
                    )
                return self.get_unique_replacement(config.name, original, config.replacement)
            return config.pattern.sub(replacer, text)

        elif config.uses_groups:
            def replacer(m):
                self.counts[config.name] += 1
                result = config.replacement
                # Find the first non-None group and substitute it for \1
                # (handles alternation patterns where the prefix may be
                # in group 1, 3, 5, etc. depending on which alternative matched)
                for i in range(1, (m.lastindex or 0) + 1):
                    grp = m.group(i)
                    if grp is not None:
                        result = result.replace(r"\1", grp)
                        break
                return result
            return config.pattern.sub(replacer, text)

        else:
            # Simple replacement - use subn for count + replace in one pass
            new_text, count = config.pattern.subn(config.replacement, text)
            if count:
                self.counts[config.name] += count
            return new_text

    def process_content(self, content: str, full_reset: bool = True) -> tuple[str, dict[str, int]]:
        """Process content with Rust acceleration or Python fallback.

        When Rust core is available, uses high-performance Rust implementation.
        Falls back to pure Python automatically if Rust fails or is unavailable.
        """
        if full_reset:
            self.reset()
        else:
            # Reset counts only, preserve unique_counters for consistency across chunks
            self.counts = defaultdict(int)

        # Try Rust core first if available
        if self._rust_core is not None:
            try:
                result, rust_counts = self._rust_core.process_content(content)
                # Merge counts
                for k, v in rust_counts.items():
                    self.counts[k] += v
                return result, dict(self.counts)
            except Exception:
                # Rust core failed, disable it and fall back to Python
                self._rust_core = None

        # Pure Python implementation follows
        # OPTIMIZATION: Lowercase entire content ONCE (not per-line)
        content_lower = content.lower()

        # Pre-fetch to avoid attribute lookup in hot loop
        all_keywords = self.matcher._all_keywords_lower
        keyword_to_patterns = self.matcher._keyword_to_patterns

        # OPTIMIZATION: Find ONLY keywords that exist in this content block
        # This reduces per-line checks from ~25 keywords to typically 1-3
        present_keywords = [kw for kw in all_keywords if kw in content_lower]

        # Fast path: no keywords present anywhere
        if not present_keywords:
            return content, {}

        # PHASE 1: Apply multiline patterns to full content
        for config in self.matcher._multiline_patterns:
            if any(kw in content_lower for kw in config.required_keywords):
                content = self.apply_pattern(config, content)
                # Update content_lower after multiline modifications
                content_lower = content.lower()

        # Build set of applicable pattern IDs based on present keywords only
        present_pattern_ids = set()
        present_patterns_list = []
        for kw in present_keywords:
            for pattern in keyword_to_patterns.get(kw, []):
                if not pattern.multiline and id(pattern) not in present_pattern_ids:
                    present_pattern_ids.add(id(pattern))
                    present_patterns_list.append(pattern)

        # Fast path: no single-line patterns apply
        if not present_pattern_ids:
            return content, dict(self.counts)

        # PHASE 2: Batch line processing for single-line patterns
        # Optimized: track modifications to avoid unnecessary string joins
        lines = content.split("\n")
        lines_lower = content_lower.split("\n")

        # Track if any line was modified
        any_modified = False

        for i, line in enumerate(lines):
            if not line:
                continue

            # OPTIMIZATION: Use pre-computed lowercase from content_lower split
            line_lower = lines_lower[i]

            # OPTIMIZATION: Only check keywords that exist in this content block
            has_keyword = False
            for kw in present_keywords:
                if kw in line_lower:
                    has_keyword = True
                    break

            if not has_keyword:
                continue

            # Collect applicable patterns (only for lines with keywords)
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

            # Apply patterns to line
            modified = line
            for config in applicable:
                modified = self.apply_pattern(config, modified)

            # Only update if actually changed
            if modified != line:
                lines[i] = modified
                any_modified = True

        # Only join if modifications were made
        if any_modified:
            return "\n".join(lines), dict(self.counts)
        else:
            return content, dict(self.counts)


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
