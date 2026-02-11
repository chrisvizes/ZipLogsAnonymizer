# ZipLogsAnonymizer

Anonymize sensitive data in log archives for safe sharing with LLMs and external parties.

This tool processes zip files containing logs (typically from Tableau Server or similar systems) and replaces sensitive information with safe placeholders, allowing you to share logs for troubleshooting without exposing credentials, internal infrastructure details, or personal information.

---

## Quick Start (For Users)

### Windows - Download and Run

1. Download `ZipLogsAnonymizer.exe` from the [Releases](../../releases) page
2. Double-click to launch the application
3. Click **Browse** and select your zip file
4. Click **Anonymize** and wait for processing (click **Cancel** to stop early if needed)
5. Click **Open Output Folder** to access your anonymized logs

**No Python or technical setup required.**

### Mac / Linux / Windows - Command Line

Mac and Linux (and Windows) users can run the tool directly from the command line:

```bash
# 1. Ensure Python 3.8+ is installed
python3 --version

# 2. Clone or download the repository
git clone <repo-url>
cd ZipLogsAnonymizer

# 3. Run on your zip file
python3 anonymizer.py /path/to/your/logs.zip

# Optional: Use the GUI (requires pywebview)
python3 gui.py
```

### Output

The tool creates:

- **`<your-zip>_anonymized.zip`** - A zip file ready for use with tools like LogShark
- **`<your-zip>_anonymized/`** - An uncompressed folder (useful for browsing/searching)

Both outputs are created by default. The original zip file is not modified.

Use `--no-zip` to skip creating the zip file, or `--no-uncompressed` to skip keeping the uncompressed folder.

---

## What Gets Anonymized

The following sensitive data patterns are detected and replaced:

### Credentials & Secrets

| Data Type             | Detection Method                                             | Example                        | Replacement                                 |
| --------------------- | ------------------------------------------------------------ | ------------------------------ | ------------------------------------------- |
| Passwords             | Context keywords (`password=`, `pwd=`, `passwd:`, `secret=`) | `password=hunter2`             | `password=PASSWORD_REDACTED`                |
| API Keys/Tokens       | Context keywords + length check (20+ chars)                  | `api_key=sk_live_abc123...`    | `API_KEY_REDACTED`                          |
| Authorization Headers | `Authorization: Bearer/Basic/Digest` patterns                | `Authorization: Bearer eyJ...` | `Authorization: Bearer AUTH_TOKEN_REDACTED` |
| Private Keys          | PEM format markers                                           | `-----BEGIN PRIVATE KEY-----`  | `PRIVATE_KEY_REDACTED`                      |
| Certificates          | PEM format markers                                           | `-----BEGIN CERTIFICATE-----`  | `CERTIFICATE_REDACTED`                      |

### Personal Information

| Data Type       | Detection Method                                  | Example                | Replacement            |
| --------------- | ------------------------------------------------- | ---------------------- | ---------------------- |
| Email Addresses | Standard email regex                              | `john.doe@company.com` | `user001@redacted.com` |
| Usernames       | Context keywords (`user=`, `username:`, `login=`) | `user=jsmith`          | `user=user001`         |
| SSNs            | Format `###-##-####`                              | `123-45-6789`          | `SSN_REDACTED`         |

### Network & Infrastructure

| Data Type            | Detection Method                                                        | Example                     | Replacement                        |
| -------------------- | ----------------------------------------------------------------------- | --------------------------- | ---------------------------------- |
| Internal IPs         | Private IP ranges (10.x, 192.168.x, 172.16-31.x)                        | `192.168.1.100`             | `10.0.0.1`                         |
| Internal Hostnames   | `.local`, `.internal`, `.corp`, `.lan`, `.intranet`, `.private` domains | `server.corp`               | `host001.redacted`                 |
| UNC Paths            | `\\server\share` pattern                                                | `\\fileserver\data`         | `\\REDACTED_SERVER\REDACTED_SHARE` |
| MAC Addresses        | Standard MAC format                                                     | `00:1A:2B:3C:4D:5E`         | `MAC_REDACTED`                     |
| Database Connections | JDBC URLs and connection strings                                        | `jdbc:mysql://db:3306/prod` | `DB_REDACTED`                      |

### Tableau-Specific

| Data Type | Detection Method | Example | Replacement |
| --- | --- | --- | --- |
| Site Names | `site=`, `"site":"..."` JSON, or `/t/SITE/` URL path | `"site":"The Information Lab"` | `"site":"entity001"` |
| Workbook Names | `workbook=`, `"wb":"..."` JSON, or URL paths (`/vizql/w/`, `/views/`, `/authoring/`) | `"wb":"DataSchoolPlacements"` | `"wb":"entity002"` |
| View Names | `"vw":"..."` JSON or URL paths (`/vizql/w/.../v/`, `/views/.../`, `/authoring/.../`) | `"vw":"PlacementGanttDash"` | `"vw":"entity003"` |
| Datasource Names | `datasource=` or `"datasource":"..."` JSON | `datasource=ProductionDB` | `datasource=entity004` |
| Project Names | `project=` or `"project":"..."` JSON | `project=Finance` | `project=entity005` |

Detection covers key=value pairs, JSON structured log fields (`"site":"..."`, `"vw":"..."`, `"wb":"..."`), and URL paths:

- `/vizql/w/WORKBOOK/v/VIEW/...` - VizQL rendering endpoints
- `/views/WORKBOOK/VIEW?...` - Direct view URLs
- `/authoring/WORKBOOK/VIEW?...` - Authoring mode URLs
- `/t/SITE/...` - Multi-site URL prefix

### Database Queries

| Data Type | Detection Method | Example | Replacement |
| --- | --- | --- | --- |
| SQL Queries | `SELECT`, `INSERT INTO`, `UPDATE`, `DELETE`, `WITH` statements (multiline) | `SELECT "t1"."name" FROM "users"` | `QUERY_REDACTED` |

SQL queries logged by Tableau's Hyper engine can contain sensitive data such as column names, table names, and string literals with personal information. Entire queries are replaced with `QUERY_REDACTED`.

### Consistency Guarantee

The same original value always maps to the same replacement throughout all files:

- `john@company.com` → `user001@redacted.com` (every occurrence)
- `192.168.1.50` → `10.1.0.1` (every occurrence)

This preserves the ability to trace issues across log files while hiding the actual values.

---

## What Is NOT Anonymized

The following are **intentionally not modified** and may still contain sensitive information:

| Data Type                   | Why Not Included                                                                            | Risk Level |
| --------------------------- | ------------------------------------------------------------------------------------------- | ---------- |
| **External/Public IPs**     | Often needed for debugging connectivity issues; less sensitive than internal infrastructure | Medium     |
| **Phone Numbers**           | High false-positive rate (version numbers, ports, timestamps look similar)                  | Low-Medium |
| **Full Names**              | Extremely difficult to detect reliably without a name database                              | Medium     |
| **Custom Application Data** | Business-specific data in JSON/XML payloads is unpredictable                                | Varies     |
| **File Paths**              | Local paths like `C:\Users\...` may reveal usernames but are often needed for debugging     | Low        |
| **Timestamps**              | Required for log analysis                                                                   | None       |
| **Error Messages**          | Required for debugging                                                                      | Low        |
| **Stack Traces**            | Required for debugging                                                                      | Low        |

**Recommendation:** Review the anonymized output before sharing if you have specific concerns about data not in the "What Gets Anonymized" list above.

---

## How It Works

### Processing Pipeline

```text
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Input Zip  │ ──► │ Categorize   │ ──► │ Anonymize   │ ──► │ Output Dir   │ ──► │ Output Zip   │
│   File      │     │ Files        │     │ Text Files  │     │ (unzipped)   │     │ (for tools)  │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘     └──────────────┘
                           │                    │
                           ▼                    ▼
                    Binary files         Text files processed
                    copied as-is         by Rust core engine
```

1. **File Categorization**: Files are sorted into text (`.log`, `.txt`, `.json`, `.xml`, `.yml`, `.yaml`, `.properties`, `.conf`, `.config`, `.html`, `.htm`) and binary (everything else)

2. **Binary Passthrough**: Binary files (images, compiled files, etc.) are copied unchanged

3. **Text Processing**: Text files are processed by a high-performance Rust core that applies regex patterns to detect and replace sensitive data

4. **Memory-Efficient Streaming**: Large files (>5MB) are processed in chunks to keep memory usage bounded, writing output directly to disk

5. **Cleanup on Failure**: If processing fails or is cancelled, the incomplete output directory is deleted to prevent accidental use of partially-anonymized data

### Performance

The tool is designed to handle large log archives (1-2GB+ zips containing thousands of files). The Rust core provides **5-15x faster processing** compared to pure Python regex.

| Technique                    | Description                                                                                                                                                       |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust Core**                | Pattern matching implemented in Rust via PyO3 for maximum throughput. All regex operations run in compiled native code.                                           |
| **Memory-Aware Concurrency** | Automatically limits parallel processing based on available RAM. Large files use streaming to avoid memory spikes.                                                |
| **Parallel Processing**      | Small files processed in parallel using ProcessPoolExecutor. Large files use ThreadPoolExecutor with chunked processing.                                          |
| **Keyword Pre-Filtering**    | Scans content once to identify which patterns could match, then only applies relevant patterns per-line. Typically reduces regex checks from ~25 to 1-3 per line. |
| **Optimized Compression**    | Output zip uses fast compression (level 1) and stores already-compressed files without re-compression.                                                            |

### Architecture

```text
ZipLogsAnonymizer/
├── gui.py               # GUI application (pywebview + D3.js treemap)
├── anonymizer.py        # Main processing logic - file handling, parallelization
├── pattern_matcher.py   # Pattern definitions and Python/Rust interface
├── gui_assets/          # Web-based GUI resources
│   ├── index.html       # Main GUI layout
│   ├── styles.css       # Styling
│   └── treemap.js       # D3.js treemap visualization
├── rust_core/           # Rust extension (anonymizer_core)
│   ├── src/lib.rs       # Rust pattern matching implementation
│   └── Cargo.toml       # Rust dependencies
├── test_anonymizer.py   # Test suite - pattern matching and edge cases
├── test_performance.py  # Performance tests - throughput, memory, consistency
├── build.py             # Build script for creating executable
└── requirements.txt     # Python dependencies
```

- **`rust_core/`**: High-performance Rust extension built with PyO3 and maturin. Implements all regex pattern matching for 5-15x speedup over Python.
- **`pattern_matcher.py`**: Defines sensitive data patterns and provides the Python interface to the Rust core. Uses natural-looking replacements (e.g., `user001` instead of `USERNAME_001`) for compatibility with log analysis tools.
- **`anonymizer.py`**: Handles zip extraction, file categorization, parallel processing, progress reporting, and output writing. Creates both uncompressed directory and zip file output.
- **`gui.py`**: Provides the graphical interface using pywebview with a D3.js treemap visualization showing real-time processing progress for each file.

---

## For Developers

### Setup

```bash
# Clone the repository
git clone <repo-url>
cd ZipLogsAnonymizer

# Install Python dependencies
pip install -r requirements.txt

# Install Rust toolchain (required)
# Visit https://rustup.rs/ or run:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the Rust extension
cd rust_core
maturin develop --release
cd ..
```

The Rust extension (`anonymizer_core`) is required. The application will fail to start without it.

### Running Tests

The project includes functional tests and performance tests:

```bash
# Run all functional tests
pytest test_anonymizer.py -v

# Run performance tests
pytest test_performance.py -v
```

### Adding New Patterns

To add a new sensitive data pattern, edit `pattern_matcher.py`:

```python
# In PatternMatcher._compile_patterns(), add:
patterns.append(
    PatternConfig(
        name="my_new_pattern",           # Category name for reporting
        pattern=re.compile(r"..."),      # Regex to match
        replacement="REDACTED",          # Replacement text (use \1 for groups)
        uses_groups=False,               # True if replacement uses capture groups
        required_keywords=frozenset(["keyword1", "keyword2"]),  # For pre-filtering
        multiline=False,                 # True for patterns spanning multiple lines
    )
)
```

**Important**: Add corresponding tests in `test_anonymizer.py` to verify the pattern works correctly.

### Command Line Usage

For scripting or automation without the GUI:

```bash
python anonymizer.py <path-to-zip-file>

# Options:
#   -w, --workers N      Number of parallel workers (default: CPU count, max 8)
#   --no-zip             Don't create output zip file (only keep uncompressed directory)
#   --no-uncompressed    Don't keep uncompressed directory (only create zip file)
```

By default, both a zip file and uncompressed directory are created. The zip file is ready for use with tools like LogShark.

### Building the Executable

The build process compiles the Rust extension and bundles everything into a standalone executable.

#### Windows

```bash
# Run the build script (builds Rust extension automatically)
python build.py
```

This creates `dist/ZipLogsAnonymizer.exe` that runs without Python or Rust installed.

#### Mac / Linux

Mac users can build a native executable, but it must be built on a Mac:

```bash
# Run the build script
python3 build.py
```

This creates `dist/ZipLogsAnonymizer` (no extension) that runs without Python installed.

**Note:** Executables built on Intel Macs won't run natively on Apple Silicon (and vice versa). For broad compatibility, Mac users can simply run the Python scripts directly rather than building an executable.

### Contributing

1. Add tests for any new patterns or features
2. Run the full test suite before submitting changes
3. Update this README if adding new pattern categories

---

## Limitations

- **Not a security guarantee**: This tool reduces risk but cannot guarantee all sensitive data is removed. Always review output for highly sensitive use cases.
- **Text files only**: Binary files are copied unchanged. Embedded text in binaries (e.g., SQLite databases) is not processed.
- **English-centric patterns**: Some patterns (like name detection if added) may not work well for non-English content.
- **No undo**: The original zip is preserved, but if you delete it, there's no way to recover the original data from the anonymized output.
- **Platform-specific executables**: Windows `.exe` files only run on Windows. Mac users should run the Python scripts directly or build their own executable on a Mac.

---

## License

Internal use only.
