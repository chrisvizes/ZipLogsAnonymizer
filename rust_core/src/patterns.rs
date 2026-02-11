//! Pattern definitions for sensitive data detection
//!
//! These patterns mirror the Python pattern_matcher.py definitions exactly
//! to ensure consistent behavior between Python and Rust implementations.

use regex::Regex;

/// Configuration for a single anonymization pattern
pub struct PatternConfig {
    pub name: &'static str,
    pub regex: Regex,
    pub replacement: &'static str,
    pub uses_groups: bool,
    pub keywords: Vec<&'static str>,
    pub multiline: bool,
    /// If true, replacement contains {UNIQUE} placeholder
    pub uses_unique: bool,
}

impl PatternConfig {
    fn new(
        name: &'static str,
        pattern: &str,
        replacement: &'static str,
        uses_groups: bool,
        keywords: Vec<&'static str>,
        multiline: bool,
        case_insensitive: bool,
    ) -> Self {
        let regex = if case_insensitive {
            Regex::new(&format!("(?i){}", pattern)).expect("Invalid regex pattern")
        } else {
            Regex::new(pattern).expect("Invalid regex pattern")
        };

        let uses_unique = replacement.contains("{UNIQUE}");

        Self {
            name,
            regex,
            replacement,
            uses_groups,
            keywords,
            multiline,
            uses_unique,
        }
    }
}

/// Build all patterns matching the Python implementation
pub fn build_patterns() -> Vec<PatternConfig> {
    vec![
        // === HIGH SPECIFICITY PATTERNS ===

        // Private keys (MULTILINE)
        PatternConfig::new(
            "private_key",
            r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----",
            "PRIVATE_KEY_REDACTED",
            false,
            vec!["-----begin"],
            true,
            false,
        ),

        // Certificates (MULTILINE)
        PatternConfig::new(
            "certificate",
            r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",
            "CERTIFICATE_REDACTED",
            false,
            vec!["-----begin certificate"],
            true,
            false,
        ),

        // Authorization headers
        PatternConfig::new(
            "auth_header",
            r"(Authorization\s*:\s*(?:Basic|Bearer|Digest)\s+)\S+",
            "${1}AUTH_TOKEN_REDACTED",
            true,
            vec!["authorization"],
            false,
            true,
        ),

        // JDBC connection strings
        PatternConfig::new(
            "db_connection",
            r#"jdbc:[a-zA-Z0-9]+://[^;\s"]+"#,
            "DB_REDACTED",
            false,
            vec!["jdbc:"],
            false,
            false,
        ),

        // UNC paths
        PatternConfig::new(
            "unc_path",
            r"\\{2,}[a-zA-Z0-9_.-]+\\{1,}[a-zA-Z0-9_.$-]+(?:\\{1,}[a-zA-Z0-9_.$-]+)*",
            r"\\\\REDACTED_SERVER\\\\REDACTED_SHARE",
            false,
            vec!["\\\\"],
            false,
            false,
        ),

        // SSN
        PatternConfig::new(
            "ssn",
            r"\b\d{3}-\d{2}-\d{4}\b",
            "SSN_REDACTED",
            false,
            vec!["-"],
            false,
            false,
        ),

        // MAC addresses
        PatternConfig::new(
            "mac_address",
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "MAC_REDACTED",
            false,
            vec![":", "-"],
            false,
            false,
        ),

        // === MEDIUM SPECIFICITY PATTERNS ===

        // Email addresses
        PatternConfig::new(
            "email",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "{UNIQUE}@redacted.com",
            false,
            vec!["@"],
            false,
            true,
        ),

        // Internal IP addresses
        PatternConfig::new(
            "internal_ip",
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b",
            "{UNIQUE}",
            false,
            vec!["10.", "192.", "172."],
            false,
            false,
        ),

        // Hostnames with internal TLDs
        PatternConfig::new(
            "hostname",
            r"\b(?:[a-zA-Z][a-zA-Z0-9-]*\.)+(?:local|internal|corp|lan|intranet|private)\b",
            "{UNIQUE}.redacted",
            false,
            vec![".local", ".internal", ".corp", ".lan", ".intranet", ".private"],
            false,
            true,
        ),

        // === CONTEXT-DEPENDENT PATTERNS ===

        // Passwords with context
        PatternConfig::new(
            "password",
            r#"((?:password|passwd|pwd|secret)\s*[=:]\s*)[^\s,;\\'"\}\]]+|("(?:password|passwd|pwd|secret)"\s*:\s*")[^"]+"#,
            "${1}PASSWORD_REDACTED",
            true,
            vec!["password", "passwd", "pwd", "secret"],
            false,
            true,
        ),

        // API keys with context
        PatternConfig::new(
            "api_key",
            r#"((?:api[_-]?key|token|bearer)\s*[=:]\s*)[a-zA-Z0-9_-]{20,}|("(?:api[_-]?key|token)"\s*:\s*")[^"]{20,}"#,
            "${1}API_KEY_REDACTED",
            true,
            vec!["api_key", "api-key", "apikey", "token", "bearer"],
            false,
            true,
        ),

        // Database connection params
        PatternConfig::new(
            "db_connection",
            r#"\b(?:Server|Data Source|User ID|uid)\s*=\s*[^;\s"]+"#,
            "DB_REDACTED",
            false,
            vec!["server=", "data source=", "user id=", "uid="],
            false,
            true,
        ),

        // Usernames with context
        PatternConfig::new(
            "username",
            r#"((?:user(?:name)?|login)\s*[=:]\s*)([a-zA-Z0-9_@.-]+)|("(?:user(?:name)?|login)"\s*:\s*")([^"]+)"#,
            "${1}{UNIQUE}",
            true,
            vec!["user=", "user:", "username", "login", "\"user\""],
            false,
            true,
        ),

        // Tableau URL path patterns - content names in URL paths
        // Must be defined BEFORE key=value tableau_entity pattern.

        // Site name from /t/SITE_NAME/...
        PatternConfig::new(
            "tableau_entity",
            r"(/t/)([^/]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/t/"],
            false,
            false,
        ),

        // VizQL workbook from /vizql/w/WORKBOOK/...
        PatternConfig::new(
            "tableau_entity",
            r"(/vizql/w/)([^/]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/vizql/"],
            false,
            false,
        ),

        // VizQL view from /vizql/w/.../v/VIEW/...
        PatternConfig::new(
            "tableau_entity",
            r"(/vizql/w/[^/]+/v/)([^/]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/vizql/"],
            false,
            false,
        ),

        // Views workbook from /views/WORKBOOK/...
        PatternConfig::new(
            "tableau_entity",
            r"(/views/)([^/]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/views/"],
            false,
            false,
        ),

        // Views view from /views/.../VIEW?...
        PatternConfig::new(
            "tableau_entity",
            r"(/views/[^/]+/)([^/?#\s]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/views/"],
            false,
            false,
        ),

        // Authoring workbook from /authoring/WORKBOOK/...
        PatternConfig::new(
            "tableau_entity",
            r"(/authoring/)([^/]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/authoring/"],
            false,
            false,
        ),

        // Authoring view from /authoring/.../VIEW?...
        PatternConfig::new(
            "tableau_entity",
            r"(/authoring/[^/]+/)([^/?#\s]+)",
            "${1}{UNIQUE}",
            true,
            vec!["/authoring/"],
            false,
            false,
        ),

        // Tableau-specific entities (key=value context)
        PatternConfig::new(
            "tableau_entity",
            r#"((?:site|workbook|datasource|project)\s*[=:]\s*)([^\s,;\\'"\}\]]+)"#,
            "${1}{UNIQUE}",
            true,
            vec!["site=", "site:", "workbook", "datasource", "project"],
            false,
            true,
        ),
    ]
}

/// Collect all unique keywords from patterns (lowercase)
pub fn collect_all_keywords(patterns: &[PatternConfig]) -> Vec<String> {
    let mut keywords: Vec<String> = patterns
        .iter()
        .flat_map(|p| p.keywords.iter().map(|k| k.to_lowercase()))
        .collect();
    keywords.sort();
    keywords.dedup();
    keywords
}
