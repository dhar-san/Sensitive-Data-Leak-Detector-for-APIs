"""
Web Application Server for Sensitive Data Leak Detector for APIs (T1-PS7).
Built with Flask, providing REST APIs, interactive dashboard, file upload,
live scanner, rule management, and multi-format report exports.
"""

from __future__ import annotations
import datetime
import io
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, request, jsonify, render_template, send_file, Response

# Ensure leakdetect package is importable
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from leakdetect.loader import load_string, load_file, LoadedItem
from leakdetect.detector import LeakDetector, Finding, Rule, PRESIDIO_AVAILABLE
from leakdetect.reporter import LeakReporter
from leakdetect.classifier import SEVERITY_ORDER, Severity, calculate_overall_risk
from leakdetect.masker import MaskingStyle

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("leakdetect.webapp")

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "web" / "templates"),
    static_folder=str(BASE_DIR / "web" / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB max upload

# Global detector instance initialized with default rules
RULES_FILE = BASE_DIR / "rules" / "default_rules.yaml"
detector_instance = LeakDetector(rules_path=RULES_FILE)


@app.route("/")
def index():
    """Renders the main Web Application Dashboard."""
    return render_template("index.html", presidio_available=PRESIDIO_AVAILABLE)


@app.route("/favicon.ico")
def favicon():
    """Serves application icon."""
    return send_file(BASE_DIR / "web" / "static" / "favicon.svg", mimetype="image/svg+xml")


@app.route("/api/samples", methods=["GET"])
def get_samples():
    """Returns available sample files for 1-click loading."""
    samples_dir = BASE_DIR / "samples"
    samples_list = [
        {
            "id": "leaky_user_pii.json",
            "name": "User Profile (PII & IDs)",
            "description": "Exposes emails, phone numbers, Indian PAN cards, and Aadhaar numbers.",
            "type": "json",
            "category": "Contact & Govt IDs",
        },
        {
            "id": "leaky_auth_tokens.json",
            "name": "Auth Session (Tokens & Keys)",
            "description": "Exposes passwords, bcrypt hashes, JWTs, Bearer headers, AWS keys & RSA private keys.",
            "type": "json",
            "category": "Credentials & Tokens",
        },
        {
            "id": "leaky_payment_cards.json",
            "name": "Checkout Response (Payment Cards)",
            "description": "Exposes credit card numbers with Luhn check validation & test masks.",
            "type": "json",
            "category": "Financial",
        },
        {
            "id": "leaky_server_logs.txt",
            "name": "API Gateway Logs (DB & Stack)",
            "description": "Exposes MongoDB/Redis URIs, internal IP subnets, file paths, and python tracebacks.",
            "type": "txt",
            "category": "Internal Info",
        },
        {
            "id": "leaky_multiline.jsonl",
            "name": "Audit Stream (JSON Lines)",
            "description": "Multi-record stream of authentication events containing emails, phones, and JWTs.",
            "type": "jsonl",
            "category": "Streaming / Logs",
        },
        {
            "id": "clean_user_response.json",
            "name": "Sanitized Clean Response",
            "description": "Fully compliant API response with zero leaks (Low/Clean risk control).",
            "type": "json",
            "category": "Benchmark Clean",
        },
        {
            "id": "malformed_response.json",
            "name": "Malformed JSON Fallback",
            "description": "Broken syntax that gracefully falls back to plain-text line scanning.",
            "type": "json",
            "category": "Edge Case",
        },
    ]

    # Preload content for fast client switching
    for s in samples_list:
        file_path = samples_dir / s["id"]
        if file_path.exists():
            s["content"] = file_path.read_text(encoding="utf-8", errors="replace")
        else:
            s["content"] = ""

    return jsonify({"samples": samples_list})


@app.route("/api/scan", methods=["POST"])
def scan_text():
    """Scans raw text/JSON passed in request body (FR-1.3, FR-3.x, FR-4.x, FR-5.x)."""
    start_time = time.time()
    payload = request.get_json(force=True, silent=True) or {}
    text_input = payload.get("text", "")
    source_name = payload.get("source_name", "api_response_payload")
    masking_style = payload.get("masking_style", "partial")
    min_severity = payload.get("min_severity", "Low")
    enable_presidio = bool(payload.get("enable_presidio", False))

    if not text_input.strip():
        return jsonify({"error": "Empty input provided. Please enter text or JSON to scan."}), 400

    loaded = load_string(text_input, name=source_name)

    # Use customized detector if masking style or presidio differs
    detector = LeakDetector(
        rules_path=RULES_FILE,
        enable_presidio=enable_presidio,
        masking_style=masking_style,
    )
    # Inherit any dynamically registered rules
    detector.rules = detector_instance.rules
    detector.allow_list = detector_instance.allow_list

    findings, masked_payload = detector.scan_item(loaded)

    # Filter by min_severity
    min_rank = SEVERITY_ORDER.get(Severity(min_severity), 1)
    filtered_findings = [
        f for f in findings
        if SEVERITY_ORDER.get(Severity(f.severity), 1) >= min_rank
    ]

    duration_ms = round((time.time() - start_time) * 1000, 2)

    # Build reporter metrics
    reporter = LeakReporter(
        findings=filtered_findings,
        files_scanned=[source_name],
        rule_set_name="Active Rule Set",
    )
    report_dict = reporter.to_dict()

    return jsonify({
        "success": True,
        "duration_ms": duration_ms,
        "input_type": loaded.file_type,
        "is_json": loaded.is_json,
        "parse_warning": loaded.error,
        "summary": report_dict["summary"],
        "top_recommendations": report_dict["top_recommendations"],
        "findings": report_dict["findings"],
        "masked_payload": masked_payload,
        "total_findings": len(filtered_findings),
    })


@app.route("/api/scan-file", methods=["POST"])
def scan_file_upload():
    """Scans one or more uploaded files (.json, .jsonl, .txt, .log) (FR-1.1, FR-1.4)."""
    start_time = time.time()
    if "files" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    uploaded_files = request.files.getlist("files")
    masking_style = request.form.get("masking_style", "partial")
    min_severity = request.form.get("min_severity", "Low")

    loaded_items: List[LoadedItem] = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        for f in uploaded_files:
            if not f.filename:
                continue
            safe_name = Path(f.filename).name
            temp_path = Path(tmp_dir) / safe_name
            f.save(temp_path)
            loaded_items.append(load_file(temp_path))

        if not loaded_items:
            return jsonify({"error": "No valid files processed"}), 400

        detector = LeakDetector(rules_path=RULES_FILE, masking_style=masking_style)
        detector.rules = detector_instance.rules
        detector.allow_list = detector_instance.allow_list

        all_findings, masked_copies = detector.scan_multiple(loaded_items)

    min_rank = SEVERITY_ORDER.get(Severity(min_severity), 1)
    filtered = [f for f in all_findings if SEVERITY_ORDER.get(Severity(f.severity), 1) >= min_rank]

    duration_ms = round((time.time() - start_time) * 1000, 2)
    scanned_names = [itm.source_name for itm in loaded_items]

    reporter = LeakReporter(findings=filtered, files_scanned=scanned_names)
    report_dict = reporter.to_dict()

    # Concatenate masked outputs for preview
    first_masked = list(masked_copies.values())[0] if masked_copies else ""

    return jsonify({
        "success": True,
        "duration_ms": duration_ms,
        "files_scanned": [Path(n).name for n in scanned_names],
        "summary": report_dict["summary"],
        "top_recommendations": report_dict["top_recommendations"],
        "findings": report_dict["findings"],
        "masked_payload": first_masked,
        "total_findings": len(filtered),
    })


@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Lists all configured detection rules and allow-list (FR-3.6, FR-3.7)."""
    rules_data = [r.to_dict() for r in detector_instance.rules]
    return jsonify({
        "rules": rules_data,
        "allow_list": sorted(list(detector_instance.allow_list)),
    })


@app.route("/api/rules", methods=["POST"])
def add_custom_rule():
    """Dynamically adds a custom detection rule (FR-3.6, TC-11)."""
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("id", f"CUSTOM-{len(detector_instance.rules)+1}")
    name = data.get("name", "Custom Rule")
    pattern = data.get("pattern")
    finding_type = data.get("type", "Secret")
    severity = data.get("severity", "Medium")
    risk = data.get("risk", "Sensitive custom indicator detected.")
    recommendation = data.get("recommendation", "Review API payload and filter exposed fields.")
    standards = data.get("standards", ["OWASP API Security Top 10"])

    if not pattern and not data.get("field_match"):
        return jsonify({"error": "Either pattern (regex) or field_match must be provided."}), 400

    try:
        new_rule = Rule(
            rule_id=rule_id,
            name=name,
            finding_type=finding_type,
            severity=severity,
            pattern=pattern,
            field_match=data.get("field_match"),
            risk=risk,
            recommendation=recommendation,
            standards=standards,
            enabled=True,
            specificity=3 if pattern else 1,
        )
        detector_instance.rules.append(new_rule)
        return jsonify({"success": True, "rule": new_rule.to_dict()})
    except Exception as exc:
        return jsonify({"error": f"Invalid rule configuration: {exc}"}), 400


@app.route("/api/rules/toggle", methods=["POST"])
def toggle_rule():
    """Enables or disables a specific detection rule (FR-3.7)."""
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("id")
    enabled = bool(data.get("enabled", True))

    for r in detector_instance.rules:
        if r.rule_id == rule_id:
            r.enabled = enabled
            return jsonify({"success": True, "id": rule_id, "enabled": enabled})

    return jsonify({"error": f"Rule '{rule_id}' not found"}), 404


@app.route("/api/export", methods=["POST"])
def export_report():
    """Exports current scan report in markdown, html, json, or csv (FR-7.4)."""
    data = request.get_json(force=True, silent=True) or {}
    format_type = data.get("format", "html").lower()
    findings_raw = data.get("findings", [])
    files_scanned = data.get("files_scanned", ["api_response"])

    findings_objects: List[Finding] = []
    for f in findings_raw:
        findings_objects.append(
            Finding(
                finding_id=f.get("finding_id", "FND-0000"),
                file_name=f.get("file", "api_response"),
                location=f.get("location", "root"),
                rule_id=f.get("rule_id", "CUSTOM"),
                rule_name=f.get("rule_name", "Sensitive Pattern"),
                finding_type=f.get("type", "Secret"),
                severity=f.get("severity", "Medium"),
                confidence=f.get("confidence", "High"),
                masked_value=f.get("masked_value", "****"),
                risk=f.get("risk", ""),
                recommendation=f.get("recommendation", ""),
                standards=f.get("standards", []),
            )
        )

    reporter = LeakReporter(findings=findings_objects, files_scanned=files_scanned)

    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if format_type == "json":
        content = reporter.to_json()
        mimetype = "application/json"
        filename = f"leak_report_{timestamp_str}.json"
    elif format_type == "csv":
        content = reporter.to_csv()
        mimetype = "text/csv"
        filename = f"leak_report_{timestamp_str}.csv"
    elif format_type == "md":
        content = reporter.to_markdown()
        mimetype = "text/markdown"
        filename = f"leak_report_{timestamp_str}.md"
    else:
        content = reporter.to_html()
        mimetype = "text/html"
        filename = f"leak_report_{timestamp_str}.html"

    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({
        "status": "healthy",
        "service": "Sensitive Data Leak Detector for APIs",
        "version": "1.0.0",
        "active_rules": len(detector_instance.rules),
        "presidio_available": PRESIDIO_AVAILABLE,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[+] Starting Sensitive Data Leak Detector Web Application on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
