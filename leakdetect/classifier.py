"""
Classifier Module for Sensitive Data Leak Detector.
Handles finding types, severity ranking, contextual escalation, confidence rating,
and overall risk scoring.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    CLEAN = "Clean"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.CLEAN: 0,
}


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingType(str, Enum):
    CONTACT_PII = "Contact PII"
    CREDENTIAL = "Credential"
    TOKEN = "Token"
    SECRET = "Secret"
    FINANCIAL = "Financial"
    GOVERNMENT_ID = "Government ID"
    INTERNAL_INFO = "Internal info"
    PERSONAL_DATA = "Personal data"
    OTHER = "Other"


# Context words indicating privileged access that escalate severity (FR-4.3)
PRIVILEGED_CONTEXT_KEYWORDS = {
    "admin",
    "root",
    "master",
    "prod",
    "production",
    "superuser",
    "system",
    "private_key",
    "signing_key",
}


def adjust_severity_for_context(
    base_severity: str,
    field_name: str,
    location_path: str,
    parent_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Escalates severity if surrounding context indicates privileged/admin role (FR-4.3)."""
    search_space = f"{field_name} {location_path}".lower()
    if parent_context:
        for k in parent_context.keys():
            search_space += f" {str(k).lower()}"

    for kw in PRIVILEGED_CONTEXT_KEYWORDS:
        if kw in search_space:
            # If base was High or Medium, escalate
            if base_severity in (Severity.HIGH.value, "High"):
                return Severity.CRITICAL.value
            elif base_severity in (Severity.MEDIUM.value, "Medium"):
                return Severity.HIGH.value

    return base_severity


def calculate_overall_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates overall risk rating and numeric score for a collection of findings (FR-4.4).
    Ratings: Critical, High, Medium, Low, Clean.
    """
    empty_counts = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }

    if not findings:
        return {
            "level": Severity.CLEAN.value,
            "score": 0,
            "counts": empty_counts,
            "badge_color": "green",
            "summary": "No sensitive data leaks detected. Payload complies with security baselines.",
        }

    counts = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }

    for f in findings:
        sev = f.get("severity", Severity.LOW.value)
        if sev in counts:
            counts[sev] += 1

    # Weighted scoring formula: Critical=25, High=15, Medium=8, Low=3 (max 100)
    raw_score = (
        counts[Severity.CRITICAL.value] * 25
        + counts[Severity.HIGH.value] * 15
        + counts[Severity.MEDIUM.value] * 8
        + counts[Severity.LOW.value] * 3
    )
    score = min(100, raw_score)

    if counts[Severity.CRITICAL.value] > 0:
        level = Severity.CRITICAL.value
        badge_color = "red"
        summary = "CRITICAL RISK: Direct credential, cryptographic key, or cardholder exposure detected."
    elif counts[Severity.HIGH.value] > 0:
        level = Severity.HIGH.value
        badge_color = "orange"
        summary = "HIGH RISK: Authentication tokens, API keys, or Government IDs detected."
    elif counts[Severity.MEDIUM.value] > 0:
        level = Severity.MEDIUM.value
        badge_color = "yellow"
        summary = "MEDIUM RISK: PII contact data or sensitive internal path info exposed."
    else:
        level = Severity.LOW.value
        badge_color = "blue"
        summary = "LOW RISK: Minor internal system information (e.g., private IPs) detected."

    return {
        "level": level,
        "score": score,
        "counts": counts,
        "badge_color": badge_color,
        "summary": summary,
    }
