"""
Unit Tests for Sensitive Data Leak Detector Web Application (app.py).
Validates UI rendering, REST scan endpoints, file upload, export formats, and rule endpoints.
"""

import io
import json
import pytest
from pathlib import Path

import app


@pytest.fixture
def client():
    app.app.config["TESTING"] = True
    with app.app.test_client() as client:
        yield client


def test_webapp_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"


def test_webapp_index_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"LeakDetect" in res.data
    assert b"Sensitive Data Leak Detector for APIs" in res.data


def test_webapp_favicon(client):
    res = client.get("/favicon.ico")
    assert res.status_code == 200
    assert res.mimetype == "image/svg+xml"


def test_webapp_get_samples(client):
    res = client.get("/api/samples")
    assert res.status_code == 200
    data = res.get_json()
    assert "samples" in data
    assert len(data["samples"]) >= 6
    sample_ids = [s["id"] for s in data["samples"]]
    assert "leaky_user_pii.json" in sample_ids
    assert "clean_user_response.json" in sample_ids


def test_webapp_scan_endpoint(client):
    payload = {
        "text": json.dumps({
            "user": "leaked_victim@enterprise.com",
            "password": "ClearTextPassword!99",
            "aws_key": "AKIAIOSFODNN7EXAMPLE"
        }),
        "masking_style": "partial",
        "min_severity": "Low",
    }
    res = client.post("/api/scan", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total_findings"] >= 3
    assert data["summary"]["overall_risk_level"] == "Critical"
    assert "masked_payload" in data
    assert "ClearTextPassword!99" not in data["masked_payload"]
    assert "AKIAIOSFODNN7EXAMPLE" not in data["masked_payload"]


def test_webapp_scan_clean_endpoint(client):
    payload = {
        "text": json.dumps({"status": "ok", "code": 200, "message": "hello world"}),
        "masking_style": "partial",
    }
    res = client.post("/api/scan", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_findings"] == 0
    assert data["summary"]["overall_risk_level"] == "Clean"


def test_webapp_scan_file_upload(client):
    file_content = b'{"admin_email": "root@company.org", "token": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.u1t1nQx2m8Y4l6b9P1a8"}'
    data = {
        "files": (io.BytesIO(file_content), "test_api_resp.json"),
        "masking_style": "partial",
        "min_severity": "Low",
    }
    res = client.post("/api/scan-file", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["total_findings"] >= 2


def test_webapp_export_reports(client):
    sample_findings = [
        {
            "finding_id": "FND-0001",
            "file": "api_test.json",
            "location": "user.email",
            "rule_id": "R-EMAIL",
            "rule_name": "Email Address",
            "type": "Contact PII",
            "severity": "Medium",
            "confidence": "High",
            "masked_value": "u***@e*****.com",
            "risk": "PII exposure",
            "recommendation": "Filter email field",
            "standards": ["GDPR Article 32"]
        }
    ]

    for fmt in ["html", "md", "csv", "json"]:
        res = client.post("/api/export", json={"format": fmt, "findings": sample_findings})
        assert res.status_code == 200
        assert len(res.data) > 20


def test_webapp_rules_and_toggle(client):
    res = client.get("/api/rules")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["rules"]) >= 10
    assert len(data["allow_list"]) >= 5

    # Toggle a rule
    rule_id = data["rules"][0]["id"]
    res_toggle = client.post("/api/rules/toggle", json={"id": rule_id, "enabled": False})
    assert res_toggle.status_code == 200
    assert res_toggle.get_json()["enabled"] is False

    # Restore
    client.post("/api/rules/toggle", json={"id": rule_id, "enabled": True})


def test_webapp_add_custom_rule(client):
    rule_data = {
        "id": "R-TEST-CUSTOM-WEB",
        "name": "Custom Key Pattern",
        "type": "Secret",
        "severity": "High",
        "pattern": r"CUST_KEY_[0-9]{8}",
        "risk": "Custom key exposure",
        "recommendation": "Revoke custom key",
    }
    res = client.post("/api/rules", json=rule_data)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Scan with custom rule
    scan_res = client.post("/api/scan", json={"text": '{"key": "CUST_KEY_12345678"}'})
    assert scan_res.status_code == 200
    matched = [f for f in scan_res.get_json()["findings"] if f["rule_id"] == "R-TEST-CUSTOM-WEB"]
    assert len(matched) == 1
