## The Scenario

1. Sharing logs to cloud LLMs is poor practice in terms of data security
2. Claude Code is really good at digging through a directory of logs to find issues
3. If we could remove all sensitive data from the logs, we may have an effective DESK tool on our hands

## What is the ziplogs.zip?

This project works on a zip file that contains logs and other information. This will typically be from a Tableau Server, but may also be from other tools like Tableau Servers Resource Management Tool. It should work on any zip file of logs. These zip files will have varying structures. The folder structure for Tableau Server is typically something like

```
ziplogs.zip
-> nodes
->-> processes
->->-> config
->->-> logs
->->->-> .log and .txt log files
->->-> manifest.json
```

## What can't we share?

Defining what it is we need to sanitize is critical to make this script effective but not immediately obvious.

### 1. Personal Identifiable Information (PII)

| What to find    | Detection strategy                                                                 | Replacement                                           |
| --------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Email addresses | Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`                            | `USER_EMAIL_001@redacted.com` (incrementing)          |
| Phone numbers   | Regex for common formats: `\+?[\d\s\-\(\)]{10,}`                                   | `PHONE_REDACTED`                                      |
| Usernames       | Context-based: look for `user=`, `username:`, login fields                         | `USER_001` (incrementing, consistent per unique user) |
| Full names      | Difficult - match against common name lists or patterns after `name=`, `fullname:` | `PERSON_001` (incrementing)                           |

> **Note:** Removing email addresses will be frustrating as sometimes we give advice that relates to specific users. However, we can manually search through the unsanitized logs to get this info when needed.

### 2. Credentials & Secrets

| What to find                | Detection strategy                                                                                   | Replacement              |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------ |
| Passwords                   | Regex for `password=`, `pwd=`, `passwd:` followed by values                                          | `PASSWORD_REDACTED`      |
| API keys                    | Regex for common patterns: long alphanumeric strings (32+ chars), patterns like `sk-`, `pk_`, `api_` | `API_KEY_REDACTED`       |
| Session tokens              | Look for `session=`, `token=`, `jwt=`, `bearer` headers                                              | `TOKEN_REDACTED`         |
| Authorization headers       | Regex: `Authorization:\s*(Basic\|Bearer\|Digest)\s+[^\s]+`                                           | `AUTH_HEADER_REDACTED`   |
| Database connection strings | Patterns with `jdbc:`, `Server=`, `Data Source=`, containing credentials                             | `DB_CONNECTION_REDACTED` |
| Private keys                | Multi-line patterns: `-----BEGIN (RSA\|DSA\|EC\|PRIVATE) KEY-----`                                   | `PRIVATE_KEY_REDACTED`   |
| Certificates                | Patterns: `-----BEGIN CERTIFICATE-----`                                                              | `CERTIFICATE_REDACTED`   |

### 3. Network & Infrastructure

| What to find          | Detection strategy                                                                                            | Replacement                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Internal IP addresses | Regex for private ranges: `10\.\d+\.\d+\.\d+`, `192\.168\.\d+\.\d+`, `172\.(1[6-9]\|2[0-9]\|3[01])\.\d+\.\d+` | `INTERNAL_IP_001` (consistent mapping) |
| External IP addresses | General IPv4 regex (excluding private): `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`                              | `EXTERNAL_IP_001` (consistent mapping) |
| IPv6 addresses        | Regex for IPv6 patterns                                                                                       | `IPV6_REDACTED`                        |
| Internal hostnames    | Patterns matching corporate naming conventions, `.local`, `.internal`, `.corp` domains                        | `HOST_001` (consistent mapping)        |
| Server paths          | UNC paths `\\\\server\\share`, absolute paths with server names                                               | `\\REDACTED_SERVER\REDACTED_PATH`      |
| MAC addresses         | Regex: `([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`                                                                | `MAC_REDACTED`                         |

### 4. Tableau-Specific Sensitive Data

| What to find              | Detection strategy                   | Replacement                                    |
| ------------------------- | ------------------------------------ | ---------------------------------------------- |
| Workbook/datasource names | May contain business context         | `Workbook/Datasource_001` (consistent mapping) |
| Site names                | Look for `site=`, site ID references | `SITE_001` (consistent mapping)                |
| Project names             | Project references in logs           | `PROJECT_001` (consistent mapping)             |
| License keys              | Tableau license patterns             | `LICENSE_REDACTED`                             |
| Customer database names   | Look for datasource connection info  | `DATABASE_001` (consistent mapping)            |

### Replacement Strategy Principles

1. **Consistency:** The same original value should always map to the same replacement (e.g., `john@company.com` always becomes `USER_EMAIL_001@redacted.com` throughout all files)
2. **Uniqueness:** Different original values get different replacements to preserve log readability (debugging still needs to distinguish between different users/servers)
3. **Context preservation:** Keep enough structure that logs remain parseable (e.g., email format stays as email format)

## How do we prove it works?

Do we need some kind of script, perhaps built by someone else, that looks for the information we are trying to remove?

Unit tests for each individual find and replace could improve our trust in their function

## What could the general structure of the process be?

1. User pulls git repo of ZipLogsAnonymizer
2. They run `ZipLogsAnonymizer <directory of ziplogs>`
3. The script unzips the directory of logs
   1. Iterates through each text file (log, txt, json) in the new directory
   2. Replaces all sensitive strings with a generic placeholder
   3. **If it fails at any point, deletes the directory it just made that may have incomplete sanitizing**
   4. Updates the user on its progress as it runs and confirms the result at the end.
      1. Reading out what kind of sensitive information was replaced and how many times would be a useful confirmation of parsing
