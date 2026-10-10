# 🛡️ Sensitive Data Leak Detector for APIs (T1-PS7)

> **Threat Detection and Security Monitoring — Problem Statement T1-PS7 (Version 1.0)**  
> An offline security inspection engine and interactive web application that scans sample API responses, identifies accidentally exposed sensitive data, classifies findings by severity, enforces strict privacy masking, and generates actionable remediation reports.

---

## 🌟 Key Capabilities (Aligned with SRS Specification)

* **Interactive Web Application & Studio**: Full graphical dashboard with real-time text/JSON scanner, drag-and-drop multi-file upload, 1-click sample presets, Chart.js visualizations, live rule manager, and multi-format report exporter.
* **Format Agnostic Loading (FR-1.x)**: Seamlessly ingests single files, folders, nested subdirectories, strings, `.json`, `.jsonl` (JSON Lines), `.txt`, and `.log` server traces.
* **Structure & Path Tracking (FR-2.x)**: Recursively parses nested JSON trees, records canonical JSON object paths (e.g. `data.users[0].email`), line numbers for plaintext, and inspects embedded strings/query parameters (FR-2.5).
* **Comprehensive Detection Suite (FR-3.x & Section 6.1)**:
  * **Contact PII**: Email addresses, Indian (+91, mobiles starting 6–9) and international phone numbers.
  * **Credentials**: Passwords under sensitive keys, bcrypt hashes (`$2b$`), MD5/SHA hashes.
  * **API Keys & Secrets**: High-entropy strings (20+ chars, Shannon entropy $\ge 3.2$), keys under `api_key`, `secret`, `client_secret`.
  * **Tokens**: JSON Web Tokens (3-part `eyJ...`), Bearer authorization headers.
  * **Cloud Credentials**: AWS access key IDs (`AKIA...`, `ASIA...`), PEM private key blocks.
  * **Financial**: Credit/debit card numbers validated via the **Luhn mod-10 algorithm**.
  * **Government IDs**: Indian Aadhaar numbers (12 digits, groups of 4), Indian PAN cards (`[A-Z]{5}[0-9]{4}[A-Z]`).
  * **Internal Topology**: Database connection strings (`mongodb://`, `jdbc:`, `postgres://`, `redis://`), private IPv4 subnets (RFC 1918: `10.x`, `172.16-31.x`, `192.168.x`), internal file paths (`C:\`, `/var/`), and stack tracebacks.
* **Sensitive Field Protection (FR-3.4)**: Flags fields named `password`, `secret`, `api_key`, `token`, `ssn` even when the format matches no known pattern.
* **Zero Raw Values Leaked (FR-5.1, NFR-1)**: Sensitive values are redacted immediately after detection. Raw credentials are never stored on disk, logged, or printed.
* **Type-Specific & Configurable Masking (FR-5.2, FR-5.3)**:
  * Emails: `j***@e*****.com`
  * Phone numbers: `+91-*****-**210`
  * Credit cards: `****-****-****-1111`
  * Secrets / Tokens: `eyJh****`, `S3****`
  * Styles: **Partial**, **Full** (`********`), and **Cryptographic SHA-256 Hash** (`[sha256:...]`).
* **Compliance Advisory (FR-6.x)**: Plain-language risk explanations and actionable fixes mapped to **OWASP API Security Top 10 (2023)**, **GDPR Article 32**, **PCI-DSS Requirement 3.4**, and **Indian DPDPA (2023)**.
* **Multi-Format Reporting (FR-7.4)**: Exports to **HTML** (with embedded charts), **Markdown**, **CSV**, and **JSON**.
* **CI/CD Integration (FR-8.4)**: Non-zero exit code thresholds for automated build pipeline gating.

---

## 📁 Project Architecture (SRS Section 10)

```
Cyberthon/
├── leakdetect/                     # Core Detection & Redaction Package
│   ├── __init__.py                 # Public package interface & version
│   ├── loader.py                   # File, folder, string & JSONL loader (FR-1.x)
│   ├── parser.py                   # JSON path traversal & embedded inspection (FR-2.x)
│   ├── detector.py                 # Rules engine, Luhn check, entropy & Presidio hook (FR-3.x)
│   ├── classifier.py               # Severity ranking, contextual escalation & scoring (FR-4.x)
│   ├── masker.py                   # Type-specific redaction & whole-payload sanitization (FR-5.x)
│   ├── advisor.py                  # Plain-language risks, fixes & compliance mapping (FR-6.x)
│   ├── reporter.py                 # Summary compiler (HTML, MD, CSV, JSON, Console) (FR-7.x)
│   └── cli.py                      # CLI entrypoint with exit codes & flags (FR-8.1 to FR-8.4)
├── rules/
│   └── default_rules.yaml          # Built-in detection rules and default allow-list
├── samples/                        # Test payloads required by SRS Section 8
│   ├── clean_user_response.json    # Compliant API response (TC-10)
│   ├── leaky_user_pii.json         # Contact PII, PAN, Aadhaar, nested arrays (TC-04, 05, 09)
│   ├── leaky_auth_tokens.json      # Passwords, bcrypt, JWTs, Bearer, AWS, private keys (TC-06, 07)
│   ├── leaky_payment_cards.json    # Valid vs invalid card numbers for Luhn test (TC-08)
│   ├── leaky_server_logs.txt       # Database URIs, private IPs, paths, tracebacks
│   ├── leaky_multiline.jsonl       # Multi-record JSON Lines audit stream (FR-1.5)
│   └── malformed_response.json     # Syntax error fallback to plain-text (TC-02)
├── web/                            # Web Application Frontend
│   ├── templates/
│   │   └── index.html              # Responsive Cyber Dashboard UI
│   └── static/
│       ├── css/style.css           # Slate Dark & Clean Light themes
│       └── js/app.js               # Frontend interactive controller & Chart.js engine
├── notebooks/
│   └── demo.ipynb                  # Interactive evaluation demo notebook (FR-8.2)
├── tests/                          # Full Automated Pytest Suite
│   ├── test_detector.py            # Validates test cases TC-01 through TC-17
│   └── test_webapp.py              # Validates Web App REST APIs, upload & export
├── app.py                          # Flask Web Application Server
└── README.md                       # Documentation & SRS Verification
```

---

## 🚀 Quick Start Guide

### 1. Launch the Web Application

To start the interactive web application:

```bash
python app.py
```

Open your browser to: **`http://localhost:5000`**

#### Web Features:
* **Live Scanner**: Paste any JSON/text payload or choose from 6 pre-loaded sample buttons.
* **File Upload**: Drag and drop `.json`, `.jsonl`, `.txt`, `.log` files for instant scanning.
* **Security Dashboard**: Live severity distribution doughnut chart, category bar chart, and searchable findings table.
* **Sanitized Payload Viewer**: Preview and copy the redacted output where raw credentials have been removed.
* **Export Center**: 1-click downloads for HTML, Markdown, CSV, or JSON reports.
* **Detection Rule Manager**: Enable/disable rules on the fly, view allow-lists, and add custom regex rules.

---

### 2. Run via Command-Line Interface (CLI)

The CLI supports all options required by **FR-8.1**, **FR-8.3**, and **FR-8.4**:

```bash
# Scan a single file with Markdown console output
python -m leakdetect.cli scan samples/leaky_user_pii.json

# Scan with custom rules and export to interactive HTML report
python -m leakdetect.cli scan samples/leaky_auth_tokens.json --format html --output report.html

# Scan directory recursively and save sanitized copies of all files
python -m leakdetect.cli scan samples/ --recursive --save-masked sanitized_outputs/

# CI/CD Pipeline check: fail build if Critical or High leaks exist
python -m leakdetect.cli scan samples/leaky_payment_cards.json --fail-on High
```

#### CLI Options:
* `path`: File or folder path to scan
* `--rules <path>`: Custom YAML/JSON rule configuration
* `--format {md,html,json,csv}`: Report format (default: `md`)
* `--output <file>`: Destination file for report
* `--min-severity {Critical,High,Medium,Low}`: Threshold filter
* `--masking-style {partial,full,hash}`: Redaction style
* `--save-masked <file/dir>`: Save sanitized copy of input
* `--fail-on {Critical,High,Medium,Low}`: Non-zero exit code for CI gating
* `--recursive`, `-r`: Ingest subdirectories recursively

---

### 3. Run the Automated Test Suite (SRS Test Cases TC-01 to TC-17)

All 17 test cases defined in **SRS Section 8** and additional web integration tests are automated:

```bash
python -m pytest -v
```

```
tests/test_detector.py::test_tc01_load_valid_json PASSED                 [  3%]
tests/test_detector.py::test_tc02_load_malformed_json PASSED             [  7%]
tests/test_detector.py::test_tc03_missing_or_unsupported_file PASSED     [ 11%]
tests/test_detector.py::test_tc04_scan_emails PASSED                     [ 15%]
tests/test_detector.py::test_tc05_scan_phone_numbers_and_rule_out_ids PASSED [ 19%]
tests/test_detector.py::test_tc06_scan_jwt_bearer_api_key PASSED         [ 23%]
tests/test_detector.py::test_tc07_sensitive_field_name_password PASSED   [ 26%]
tests/test_detector.py::test_tc08_credit_card_luhn_validation PASSED     [ 30%]
tests/test_detector.py::test_tc09_nested_json_paths PASSED               [ 34%]
tests/test_detector.py::test_tc10_clean_response PASSED                  [ 38%]
tests/test_detector.py::test_tc11_custom_rule_yaml PASSED                [ 42%]
tests/test_detector.py::test_tc12_no_raw_values_leaked PASSED            [ 46%]
tests/test_detector.py::test_tc13_export_formats PASSED                  [ 50%]
tests/test_detector.py::test_tc14_minimum_severity PASSED                [ 53%]
tests/test_detector.py::test_tc15_presidio_toggle PASSED                 [ 57%]
tests/test_detector.py::test_tc16_performance_large_payload PASSED       [ 61%]
tests/test_detector.py::test_tc17_allow_listed_value PASSED              [ 65%]
tests/test_webapp.py::test_webapp_health PASSED                          [ 69%]
tests/test_webapp.py::test_webapp_index_html PASSED                      [ 73%]
tests/test_webapp.py::test_webapp_get_samples PASSED                     [ 76%]
tests/test_webapp.py::test_webapp_scan_endpoint PASSED                   [ 80%]
tests/test_webapp.py::test_webapp_scan_clean_endpoint PASSED             [ 84%]
tests/test_webapp.py::test_webapp_scan_file_upload PASSED                [ 88%]
tests/test_webapp.py::test_webapp_export_reports PASSED                  [ 92%]
tests/test_webapp.py::test_webapp_rules_and_toggle PASSED                [ 96%]
tests/test_webapp.py::test_webapp_add_custom_rule PASSED                 [100%]
============================== 26 passed in 4.40s ==============================
```

---

### 4. Interactive Jupyter Notebook (FR-8.2)

Open `notebooks/demo.ipynb` in VS Code or Jupyter:
```bash
jupyter notebook notebooks/demo.ipynb
```
Follow the step-by-step walkthrough covering ingestion, JSON path resolution, rule execution, Pandas table inspection, masking verification, and report generation.

---

## 🔒 Masking Rules (FR-5.2)

| Data Type | Raw Input Example | Masked Output |
| :--- | :--- | :--- |
| **Email** | `asha.k@mailbox.test` | `a***@m******.test` |
| **Phone (+91)** | `+91 98765 43210` | `+91-*****-**210` |
| **Credit Card** | `4111 1111 1111 1111` | `****-****-****-1111` |
| **JWT / Secret** | `eyJhbGciOiJIUzI1Ni...` | `eyJh****` |
| **Password** | `S3cret!2024` | `S3****` |
| **Aadhaar** | `2345 6789 0123` | `****-****-0123` |
| **PAN Card** | `ABCDE1234F` | `AB*****F` |
| **DB Connection** | `mongodb://admin:pass@host` | `mongodb://****:****@host` |
| **Private IP** | `192.168.1.100` | `192.168.***.***` |

---

## 🛡️ Standards & Compliance Framework Mapping (FR-6.4)

* **OWASP API Security Top 10 (2023)**:
  * `API1:2023` Broken Object Level Authorization (BOLA)
  * `API2:2023` Broken Authentication (Hardcoded credentials, JWTs, Bearer headers)
  * `API3:2023` Broken Object Property Level Authorization / Excessive Data Exposure
  * `API8:2023` Security Misconfiguration (Stack traces, debug paths, database URIs)
* **GDPR (General Data Protection Regulation)**:
  * Article 32: Security of Processing (Personal data confidentiality)
* **PCI-DSS v4.0**:
  * Requirement 3.4: Render PAN unreadable anywhere it is stored or transmitted
* **Indian DPDPA (2023) & Aadhaar Act (2016)**:
  * Mandatory masking of statutory identifiers
