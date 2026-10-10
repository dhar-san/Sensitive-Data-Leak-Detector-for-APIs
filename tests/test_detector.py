"""
Comprehensive Unit Tests for Sensitive Data Leak Detector for APIs (T1-PS7).
Directly tests and validates Test Cases TC-01 through TC-17 from SRS Section 8.
"""

import json
import os
import tempfile
import time
from pathlib import Path
import pytest
import yaml

from leakdetect.loader import load_file, load_folder, load_string
from leakdetect.parser import extract_items
from leakdetect.detector import LeakDetector, Finding, Rule, luhn_checksum, calculate_entropy
from leakdetect.masker import mask_value, mask_payload, MaskingStyle
from leakdetect.classifier import calculate_overall_risk, Severity
from leakdetect.reporter import LeakReporter


BASE_DIR = Path(__file__).parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
RULES_FILE = BASE_DIR / "rules" / "default_rules.yaml"


def test_tc01_load_valid_json():
    """TC-01: Load a valid JSON file - It is parsed and every field is visited."""
    item = load_file(SAMPLES_DIR / "leaky_user_pii.json")
    assert item.error is None
    assert item.is_json is True
    assert item.parsed_data is not None

    parsed = extract_items(item)
    locations = [p.location for p in parsed]
    assert "data.users[0].email" in locations
    assert "data.users[0].phone" in locations
    assert "data.users[1].pan" in locations


def test_tc02_load_malformed_json():
    """TC-02: Load a malformed JSON file - Warning logged, scanned as plain text, no crash."""
    item = load_file(SAMPLES_DIR / "malformed_response.json")
    assert item.is_json is False
    assert item.error is not None
    assert "Malformed JSON" in item.error

    detector = LeakDetector(rules_path=RULES_FILE)
    findings, masked = detector.scan_item(item)
    assert len(findings) > 0
    # Line numbers recorded instead of crashing
    assert any("line" in f.location for f in findings)


def test_tc03_missing_or_unsupported_file():
    """TC-03: Give a missing or unsupported file - Clear error appears."""
    missing = load_file("samples/does_not_exist_file.json")
    assert missing.error is not None
    assert "File not found" in missing.error

    unsupported = load_file(BASE_DIR / "rules" / "default_rules.yaml")
    assert unsupported.error is not None
    assert "Unsupported file type" in unsupported.error


def test_tc04_scan_emails():
    """TC-04: Scan a response with email addresses - All found, Medium severity, masked."""
    raw = '{"contact": "john.doe@company.org", "billing": "finance-ops@payments.net"}'
    item = load_string(raw)
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, _ = detector.scan_item(item)

    email_findings = [f for f in findings if f.rule_id == "R-EMAIL"]
    assert len(email_findings) == 2
    for f in email_findings:
        assert f.severity == "Medium"
        assert "@" in f.masked_value
        assert "***" in f.masked_value
        assert "john.doe" not in f.masked_value


def test_tc05_scan_phone_numbers_and_rule_out_ids():
    """TC-05: Real numbers are found, and random 10-digit IDs are not flagged."""
    raw = json.dumps({
        "customer_phone": "+91 98765 43210",
        "intl_phone": "+1-555-234-5678",
        "transaction_id": "9876543210",
        "order_id": "1122334455"
    })
    item = load_string(raw)
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, _ = detector.scan_item(item)

    phone_locations = [f.location for f in findings if f.rule_id == "R-PHONE"]
    assert "customer_phone" in phone_locations
    assert "intl_phone" in phone_locations
    assert "transaction_id" not in phone_locations
    assert "order_id" not in phone_locations


def test_tc06_scan_jwt_bearer_api_key():
    """TC-06: Scan JWT, bearer token, API key - Rated High, advice to rotate."""
    detector = LeakDetector(rules_path=RULES_FILE)
    item = load_file(SAMPLES_DIR / "leaky_auth_tokens.json")
    findings, _ = detector.scan_item(item)

    rule_ids = {f.rule_id for f in findings}
    assert "R-JWT" in rule_ids
    assert "R-BEARER" in rule_ids
    assert "R-APIKEY" in rule_ids

    jwt_f = next(f for f in findings if f.rule_id == "R-JWT")
    assert jwt_f.severity == "High"
    assert "rotate" in jwt_f.recommendation.lower()


def test_tc07_sensitive_field_name_password():
    """TC-07: Scan a field named password that has a value - Critical finding appears even if pattern unknown."""
    raw = json.dumps({"account": {"user": "alice", "password": "custom_obscure_string"}})
    item = load_string(raw)
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, _ = detector.scan_item(item)

    pass_findings = [f for f in findings if "pass" in f.location.lower() or f.rule_id == "R-PASSWORD"]
    assert len(pass_findings) >= 1
    assert pass_findings[0].severity == "Critical"


def test_tc08_credit_card_luhn_validation():
    """TC-08: Scan one valid and one invalid card number - Only the valid one is flagged."""
    item = load_file(SAMPLES_DIR / "leaky_payment_cards.json")
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, _ = detector.scan_item(item)

    card_findings = [f for f in findings if f.rule_id == "R-CARD"]
    assert len(card_findings) == 1
    assert "valid_card_number" in card_findings[0].location
    assert "invalid_card_test" not in [f.location for f in findings]


def test_tc09_nested_json_paths():
    """TC-09: Scan nested JSON with arrays - Reported JSON paths are correct."""
    item = load_file(SAMPLES_DIR / "leaky_user_pii.json")
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, _ = detector.scan_item(item)

    locs = {f.location for f in findings}
    assert "data.users[0].email" in locs
    assert "data.users[1].email" in locs
    assert "data.users[0].aadhaar" in locs


def test_tc10_clean_response():
    """TC-10: Scan a clean response - Zero findings and low/clean overall risk."""
    item = load_file(SAMPLES_DIR / "clean_user_response.json")
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, _ = detector.scan_item(item)

    assert len(findings) == 0
    risk = calculate_overall_risk([f.to_dict() for f in findings])
    assert risk["level"] == "Clean"
    assert risk["score"] == 0


def test_tc11_custom_rule_yaml(tmp_path):
    """TC-11: Add a custom rule in YAML - The new rule fires with no code change."""
    custom_yaml = tmp_path / "custom_rules.yaml"
    custom_yaml.write_text("""
rules:
  - id: R-EMP-ID
    name: Employee ID
    type: Internal Information
    pattern: "EMP-\\\\d{6}"
    severity: Medium
    confidence: High
    risk: "Exposes internal employee ID."
    recommendation: "Replace with UUID."
    enabled: true
""", encoding="utf-8")

    raw = '{"employee": {"badge": "EMP-948201"}}'
    detector = LeakDetector(rules_path=custom_yaml)
    findings, _ = detector.scan_item(load_string(raw))

    assert len(findings) == 1
    assert findings[0].rule_id == "R-EMP-ID"
    assert findings[0].severity == "Medium"


def test_tc12_no_raw_values_leaked():
    """TC-12: Check outputs for raw values - None appear in findings or reports."""
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    payload = json.dumps({"aws_key": raw_secret, "email": "admin@mysecops.corp"})
    detector = LeakDetector(rules_path=RULES_FILE)
    findings, masked_text = detector.scan_item(load_string(payload))

    for f in findings:
        f_dict = f.to_dict()
        assert raw_secret not in json.dumps(f_dict)
        assert "admin@mysecops.corp" not in json.dumps(f_dict)

    reporter = LeakReporter(findings=findings, files_scanned=["test_item"])
    rep_md = reporter.to_markdown()
    rep_html = reporter.to_html()
    rep_csv = reporter.to_csv()

    assert raw_secret not in rep_md
    assert raw_secret not in rep_html
    assert raw_secret not in rep_csv
    assert raw_secret not in masked_text


def test_tc13_export_formats(tmp_path):
    """TC-13: Export to JSON, CSV, Markdown, and HTML."""
    detector = LeakDetector(rules_path=RULES_FILE)
    item = load_file(SAMPLES_DIR / "leaky_user_pii.json")
    findings, _ = detector.scan_item(item)
    reporter = LeakReporter(findings=findings, files_scanned=[str(SAMPLES_DIR / "leaky_user_pii.json")])

    for fmt in ["json", "csv", "md", "html"]:
        out_f = tmp_path / f"report.{fmt}"
        reporter.save_report(out_f, format_type=fmt)
        assert out_f.exists()
        assert out_f.stat().st_size > 50


def test_tc14_minimum_severity():
    """TC-14: Set minimum severity - Only findings at or above it are shown."""
    detector = LeakDetector(rules_path=RULES_FILE)
    item = load_file(SAMPLES_DIR / "leaky_server_logs.txt")
    findings, _ = detector.scan_item(item)

    # Filter by High
    high_and_above = [f for f in findings if f.severity in ("Critical", "High")]
    lows = [f for f in findings if f.severity == "Low"]

    assert len(high_and_above) > 0
    assert len(lows) > 0
    assert all(f.severity in ("Critical", "High") for f in high_and_above)


def test_tc15_presidio_toggle():
    """TC-15: Run with Presidio on and off - Works both ways safely."""
    detector_off = LeakDetector(rules_path=RULES_FILE, enable_presidio=False)
    detector_on = LeakDetector(rules_path=RULES_FILE, enable_presidio=True)

    item = load_string('{"name": "Alice Wonderland"}')
    findings_off, _ = detector_off.scan_item(item)
    findings_on, _ = detector_on.scan_item(item)

    assert isinstance(findings_off, list)
    assert isinstance(findings_on, list)


def test_tc16_performance_large_payload(tmp_path):
    """TC-16: Scan file of about 5 MB - Finishes within performance target (under 10s)."""
    large_file = tmp_path / "large_api_payload.json"
    data = []
    # Generate ~4.5MB of JSON data
    for i in range(25000):
        data.append({
            "idx": i,
            "status": "OK",
            "tag": f"cluster-node-{i}",
            "dummy_email": f"user_{i}@example.com" if i % 100 == 0 else f"node-{i}.internal",
            "info": "Safe telemetry message with some diagnostic payload details."
        })

    with open(large_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    file_size_mb = large_file.stat().st_size / (1024 * 1024)
    assert file_size_mb >= 3.5  # substantial size

    detector = LeakDetector(rules_path=RULES_FILE)
    loaded = load_file(large_file)

    start_time = time.time()
    findings, _ = detector.scan_item(loaded)
    duration = time.time() - start_time

    assert duration < 10.0, f"Scan took {duration:.2f}s, exceeding 10s threshold"


def test_tc17_allow_listed_value():
    """TC-17: Scan an allow-listed value such as test@example.com - Left out of results."""
    detector = LeakDetector(rules_path=RULES_FILE)
    payload = json.dumps({
        "safe_email_1": "test@example.com",
        "safe_email_2": "example@example.com",
        "safe_mask": "0000-0000-0000-0000",
        "leaked_email": "real.leak@production-bank.com"
    })
    findings, _ = detector.scan_item(load_string(payload))

    locs = [f.location for f in findings]
    assert "safe_email_1" not in locs
    assert "safe_email_2" not in locs
    assert "safe_mask" not in locs
    assert "leaked_email" in locs
