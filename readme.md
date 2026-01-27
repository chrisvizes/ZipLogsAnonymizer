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

### Mac / Linux - Command Line

Mac and Linux users can run the tool directly from the command line:

```bash
# 1. Ensure Python 3.8+ is installed
python3 --version

# 2. Clone or download the repository
git clone <repo-url>
cd ZipLogsAnonymizer

# 3. Run on your zip file
python3 anonymizer.py /path/to/your/logs.zip

# Optional: Use the GUI (requires tkinter)
python3 gui.py
```

### Output

The tool creates a folder named `<your-zip>_anonymized` containing all files with sensitive data redacted. The original zip file is not modified.

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

| Data Type       | Detection Method                                  | Example                | Replacement              |
| --------------- | ------------------------------------------------- | ---------------------- | ------------------------ |
| Email Addresses | Standard email regex                              | `john.doe@company.com` | `EMAIL_001@redacted.com` |
| Usernames       | Context keywords (`user=`, `username:`, `login=`) | `user=jsmith`          | `user=USERNAME_001`      |
| SSNs            | Format `###-##-####`                              | `123-45-6789`          | `SSN_REDACTED`           |

### Network & Infrastructure

| Data Type            | Detection Method                                                        | Example                     | Replacement                        |
| -------------------- | ----------------------------------------------------------------------- | --------------------------- | ---------------------------------- |
| Internal IPs         | Private IP ranges (10.x, 192.168.x, 172.16-31.x)                        | `192.168.1.100`             | `INTERNAL_IP_001`                  |
| Internal Hostnames   | `.local`, `.internal`, `.corp`, `.lan`, `.intranet`, `.private` domains | `server.corp`               | `HOSTNAME_001.redacted`            |
| UNC Paths            | `\\server\share` pattern                                                | `\\fileserver\data`         | `\\REDACTED_SERVER\REDACTED_SHARE` |
| MAC Addresses        | Standard MAC format                                                     | `00:1A:2B:3C:4D:5E`         | `MAC_REDACTED`                     |
| Database Connections | JDBC URLs and connection strings                                        | `jdbc:mysql://db:3306/prod` | `DB_REDACTED`                      |

### Tableau-Specific

| Data Type        | Detection Method      | Example                   | Replacement                     |
| ---------------- | --------------------- | ------------------------- | ------------------------------- |
| Site Names       | `site=` context       | `site=CustomerPortal`     | `site=TABLEAU_ENTITY_001`       |
| Workbook Names   | `workbook=` context   | `workbook=SalesReport`    | `workbook=TABLEAU_ENTITY_002`   |
| Datasource Names | `datasource=` context | `datasource=ProductionDB` | `datasource=TABLEAU_ENTITY_003` |
| Project Names    | `project=` context    | `project=Finance`         | `project=TABLEAU_ENTITY_004`    |

### Consistency Guarantee

The same original value always maps to the same replacement throughout all files:

- `john@company.com` → `EMAIL_001@redacted.com` (every occurrence)
- `192.168.1.50` → `INTERNAL_IP_001` (every occurrence)

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

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  Input Zip  │ ──► │ Categorize   │ ──► │ Anonymize   │ ──► │ Output Dir   │
│   File      │     │ Files        │     │ Text Files  │     │ (unzipped)   │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
                           │                    │
                           ▼                    ▼
                    Binary files         Text files scanned
                    copied as-is         for sensitive patterns
```

1. **File Categorization**: Files are sorted into text (`.log`, `.txt`, `.json`, `.xml`, `.yml`, `.yaml`, `.properties`, `.conf`, `.config`, `.html`) and binary (everything else)

2. **Binary Passthrough**: Binary files (images, compiled files, etc.) are copied unchanged

3. **Text Processing**: Each text file is scanned line-by-line for sensitive patterns using optimized regex matching

4. **Immediate Write**: Processed files are written to disk immediately (not held in memory)

5. **Cleanup on Failure**: If processing fails partway through, the incomplete output directory is deleted to prevent accidental use of partially-anonymized data

### Performance Optimizations

The tool is designed to handle large log archives (500MB - 2GB zips containing thousands of files):

| Challenge              | Solution                                                                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Memory usage**       | Stream processing - files are read, processed, and written one at a time rather than loading the entire zip into memory                       |
| **Large files (>5MB)** | Processed serially in the main process to avoid overhead of serializing large data to worker processes                                        |
| **Small files**        | Processed in parallel across multiple CPU cores (up to 8 workers)                                                                             |
| **Regex performance**  | Pre-filtering with keyword checks - lines without relevant keywords (like `@`, `password`, `jdbc:`) skip regex entirely, reducing work by ~5x |
| **Pattern matching**   | Line-by-line processing with early exit - each line only runs against patterns whose keywords appear in that line                             |

### Architecture

```
ZipLogsAnonymizer/
├── gui.py              # GUI application (tkinter) - user interface
├── anonymizer.py       # Main processing logic - file handling, parallelization
├── pattern_matcher.py  # Pattern definitions and matching logic
├── test_anonymizer.py  # Test suite (105 tests)
├── build.py            # Build script for creating executable
└── requirements.txt    # Python dependencies
```

- **`pattern_matcher.py`**: Defines all sensitive data patterns with their regex, replacement text, and required keywords for pre-filtering
- **`anonymizer.py`**: Handles zip extraction, file categorization, parallel processing, progress display, and output writing
- **`gui.py`**: Provides the graphical interface wrapping the core logic

---

## For Developers

### Setup

```bash
# Clone the repository
git clone <repo-url>
cd ZipLogsAnonymizer

# Install development dependencies
pip install -r requirements.txt
```

### Running Tests

The project includes 105 tests covering pattern matching, edge cases, and output integrity:

```bash
pytest test_anonymizer.py -v
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
#   -w, --workers N    Number of parallel workers (default: CPU count, max 8)
```

### Building the Executable

#### Windows

```bash
# Install PyInstaller
pip install pyinstaller

# Run the build script
python build.py
```

This creates `dist/ZipLogsAnonymizer.exe` (~11MB) that runs without Python installed.

#### Mac / Linux

Mac users can build a native executable, but it must be built on a Mac:

```bash
# Install PyInstaller
pip3 install pyinstaller

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
