"""
Detector Module for Sensitive Data Leak Detector (T1-PS7).
Executes built-in and custom regex rules, sensitive field name checks,
entropy & Luhn validation, deduplication, and Presidio integration.
"""

from __future__ import annotations
import json
import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from .loader import LoadedItem
from .parser import ParsedItem, extract_items
from .masker import mask_value, mask_payload, MaskingStyle
from .classifier import Severity, Confidence, FindingType, adjust_severity_for_context, SEVERITY_ORDER
from .advisor import get_advice_for_rule

logger = logging.getLogger("leakdetect.detector")

# Try optional presidio import
try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for string randomness detection."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def luhn_checksum(card_str: str) -> bool:
    """Validates credit card numbers using the standard Luhn mod 10 check."""
    digits = [int(c) for c in card_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Filter repeated digits like 0000000000000000 or 1111111111111111 (unless valid test)
    if len(set(digits)) == 1 and digits[0] == 0:
        return False

    total = 0
    reversed_digits = digits[::-1]
    for i, d in enumerate(reversed_digits):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d

    return total % 10 == 0


def is_valid_phone(phone_str: str, key_name: str) -> bool:
    """Validates phone number to rule out random numeric IDs (FR-3.9, TC-05)."""
    digits = [c for c in phone_str if c.isdigit()]
    if len(digits) < 10 or len(digits) > 13:
        return False

    # Discard repeated/trivial digit sequences
    if len(set(digits)) <= 2:
        return False

    # If field name indicates an ID and string has no phone-specific formatting
    key_lower = key_name.lower()
    if any(key_lower == k or key_lower.endswith(f"_{k}") or key_lower.endswith("id")
           for k in ["id", "tx_id", "transaction_id", "order_id", "account_id", "seq"]):
        if not phone_str.startswith("+") and not any(sep in phone_str for sep in ["-", " ", "(", ")"]):
            return False

    return True


class Rule:
    """Represents an active detection rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        finding_type: str,
        severity: str,
        confidence: str = Confidence.HIGH.value,
        pattern: Optional[str] = None,
        field_match: Optional[str] = None,
        min_length: int = 0,
        min_entropy: float = 0.0,
        luhn_validation: bool = False,
        enabled: bool = True,
        risk: str = "",
        recommendation: str = "",
        standards: Optional[List[str]] = None,
        specificity: int = 1,
    ):
        self.rule_id = rule_id
        self.name = name
        self.finding_type = finding_type
        self.severity = severity
        self.confidence = confidence
        self.pattern_str = pattern
        self.pattern = re.compile(pattern) if pattern else None
        self.field_match_str = field_match
        self.field_match = re.compile(field_match, re.IGNORECASE) if field_match else None
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.luhn_validation = luhn_validation
        self.enabled = enabled
        self.risk = risk
        self.recommendation = recommendation
        self.standards = standards or []
        self.specificity = specificity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "type": self.finding_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "pattern": self.pattern_str,
            "field_match": self.field_match_str,
            "enabled": self.enabled,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "standards": self.standards,
        }


class Finding:
    """Represents a sanitized security finding (FR-7.1, NFR-1).
    Raw value is deliberately excluded from stored fields.
    """

    def __init__(
        self,
        finding_id: str,
        file_name: str,
        location: str,
        rule_id: str,
        rule_name: str,
        finding_type: str,
        severity: str,
        confidence: str,
        masked_value: str,
        risk: str,
        recommendation: str,
        standards: Optional[List[str]] = None,
    ):
        self.finding_id = finding_id
        self.file_name = file_name
        self.location = location
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.type = finding_type
        self.severity = severity
        self.confidence = confidence
        self.masked_value = masked_value
        self.risk = risk
        self.recommendation = recommendation
        self.standards = standards or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "file": self.file_name,
            "location": self.location,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "masked_value": self.masked_value,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "standards": self.standards,
        }


class LeakDetector:
    """Core detector engine coordinating rule execution, deduplication, and masking."""

    # Sensitive field names to flag even with unknown format (FR-3.4)
    SENSITIVE_FIELD_NAMES = {
        "password",
        "passwd",
        "pwd",
        "user_password",
        "secret",
        "api_key",
        "apikey",
        "client_secret",
        "auth_token",
        "access_token",
        "private_key",
        "ssn",
        "credit_card",
    }

    def __init__(
        self,
        rules_path: Optional[str | Path] = None,
        enable_presidio: bool = False,
        masking_style: str = MaskingStyle.PARTIAL.value,
    ):
        self.rules: List[Rule] = []
        self.allow_list: Set[str] = set()
        self.masking_style = masking_style
        self.enable_presidio = enable_presidio and PRESIDIO_AVAILABLE
        self.presidio_analyzer = None

        if self.enable_presidio:
            try:
                self.presidio_analyzer = AnalyzerEngine()
            except Exception as e:
                logger.warning("Could not initialize Presidio Analyzer: %s", e)
                self.enable_presidio = False

        if rules_path:
            self.load_rules(rules_path)
        else:
            default_yaml = Path(__file__).parent.parent / "rules" / "default_rules.yaml"
            if default_yaml.exists():
                self.load_rules(default_yaml)

    def load_rules(self, rules_file: str | Path) -> None:
        """Loads rules and allow_list from a YAML or JSON file (FR-3.6)."""
        path = Path(rules_file)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {path}")

        raw_text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw_text) or {}
        else:
            data = json.loads(raw_text)

        # Allow-list
        if "allow_list" in data and isinstance(data["allow_list"], list):
            self.allow_list.update(str(item).strip() for item in data["allow_list"])

        # Rules
        rules_list = data.get("rules", [])
        spec_map = {
            "R-PRIVKEY": 5,
            "R-AWS": 5,
            "R-DBCONN": 5,
            "R-BEARER": 4,
            "R-JWT": 3,
            "R-CARD": 3,
            "R-EMAIL": 3,
            "R-AADHAAR": 3,
            "R-PAN": 3,
            "R-PHONE": 3,
            "R-PASSWORD": 3,
        }
        for r_data in rules_list:
            rid = r_data.get("id", f"CUSTOM-{len(self.rules)+1}")
            spec = spec_map.get(rid, 2 if r_data.get("pattern") else 1)
            rule = Rule(
                rule_id=rid,
                name=r_data.get("name", "Custom Rule"),
                finding_type=r_data.get("type", FindingType.SECRET.value),
                severity=r_data.get("severity", Severity.HIGH.value),
                confidence=r_data.get("confidence", Confidence.HIGH.value),
                pattern=r_data.get("pattern"),
                field_match=r_data.get("field_match"),
                min_length=r_data.get("min_length", 0),
                min_entropy=float(r_data.get("min_entropy", 0.0)),
                luhn_validation=bool(r_data.get("luhn_validation", False)),
                enabled=bool(r_data.get("enabled", True)),
                risk=r_data.get("risk", ""),
                recommendation=r_data.get("recommendation", ""),
                standards=r_data.get("standards", []),
                specificity=spec,
            )
            self.rules.append(rule)

    def is_allow_listed(self, raw_value: str) -> bool:
        """Checks if a value belongs to the configured allow-list (FR-3.9)."""
        val_lower = raw_value.strip().lower()
        for allowed in self.allow_list:
            if allowed.lower() == val_lower or allowed.lower() in val_lower:
                return True
        return False

    def scan_item(self, loaded: LoadedItem) -> Tuple[List[Finding], str]:
        """Scans a LoadedItem, produces list of Findings and a sanitized payload copy."""
        parsed_items = extract_items(loaded)
        raw_candidates: List[Tuple[ParsedItem, Rule, str]] = []
        raw_to_masked_map: Dict[str, str] = {}
        finding_counter = 1

        for item in parsed_items:
            val_str = item.value_str.strip()
            if not val_str:
                continue

            # Check allow-list
            if self.is_allow_listed(val_str):
                continue

            matched_rules_for_item: List[Tuple[Rule, str]] = []

            # 1. Evaluate configured rules
            for rule in self.rules:
                if not rule.enabled:
                    continue

                matched_substring: Optional[str] = None

                # Rule with field_match: check if field name matches
                field_matched = False
                if rule.field_match and item.key_name:
                    if rule.field_match.search(item.key_name):
                        field_matched = True
                        matched_substring = val_str

                # Rule with pattern: check if value matches regex
                if rule.pattern:
                    match = rule.pattern.search(val_str)
                    if match:
                        candidate_str = match.group(0).strip()
                        # Apply validations
                        valid = True
                        if rule.luhn_validation and not luhn_checksum(candidate_str):
                            valid = False
                        if rule.rule_id == "R-PHONE" and not is_valid_phone(candidate_str, item.key_name):
                            valid = False
                        if rule.min_entropy > 0 and calculate_entropy(candidate_str) < rule.min_entropy:
                            valid = False
                        if rule.min_length > 0 and len(candidate_str) < rule.min_length:
                            valid = False
                        
                        if valid:
                            matched_substring = candidate_str

                # If rule has entropy/length requirements on field match
                if field_matched and not rule.pattern:
                    if rule.min_entropy > 0 and calculate_entropy(val_str) < rule.min_entropy:
                        matched_substring = None
                    if rule.min_length > 0 and len(val_str) < rule.min_length:
                        matched_substring = None

                if matched_substring and not self.is_allow_listed(matched_substring):
                    matched_rules_for_item.append((rule, matched_substring))

            # 2. FR-3.4: Flag values stored under sensitive field names even without pattern match
            if item.key_name and item.key_name.lower() in self.SENSITIVE_FIELD_NAMES:
                already_matched_ids = {r.rule_id for r, _ in matched_rules_for_item}
                if "R-PASSWORD" not in already_matched_ids and "R-APIKEY" not in already_matched_ids:
                    # Generic sensitive field flag
                    sev = Severity.CRITICAL.value if "pass" in item.key_name.lower() else Severity.HIGH.value
                    ftype = FindingType.CREDENTIAL.value if "pass" in item.key_name.lower() else FindingType.SECRET.value
                    field_rule = Rule(
                        rule_id="R-SENSITIVE-FIELD",
                        name=f"Exposed {item.key_name}",
                        finding_type=ftype,
                        severity=sev,
                        confidence=Confidence.HIGH.value,
                        risk=f"Sensitive field '{item.key_name}' exposed directly in API response.",
                        recommendation=f"Omit '{item.key_name}' or mask prior to returning payload.",
                        standards=["OWASP API3:2023 Broken Object Property Level Authorization"],
                    )
                    matched_rules_for_item.append((field_rule, val_str))

            # 3. Optional Presidio hook for personal names (FR-3.8)
            if self.enable_presidio and self.presidio_analyzer and len(val_str) > 2:
                try:
                    pres_results = self.presidio_analyzer.analyze(
                        text=val_str,
                        entities=["PERSON", "LOCATION"],
                        language="en",
                    )
                    for pres in pres_results:
                        if pres.score >= 0.75:
                            p_sub = val_str[pres.start:pres.end]
                            p_rule = Rule(
                                rule_id="R-NAME",
                                name="Presidio Entity Detection",
                                finding_type=FindingType.PERSONAL_DATA.value,
                                severity=Severity.LOW.value,
                                confidence=Confidence.MEDIUM.value,
                                risk="Detected personal entity (name or location) in response data.",
                                recommendation="Assess privacy compliance (GDPR/DPDPA) before exposing identity fields.",
                                standards=["GDPR Article 4"],
                            )
                            matched_rules_for_item.append((p_rule, p_sub))
                except Exception as ex:
                    logger.debug("Presidio scan skipped: %s", ex)

            # FR-3.10: Deduplication - Pick the single most severe and specific rule match for this item
            if matched_rules_for_item:
                best_rule, matched_str = max(
                    matched_rules_for_item,
                    key=lambda pair: (
                        SEVERITY_ORDER.get(Severity(pair[0].severity), 1),
                        getattr(pair[0], "specificity", 1),
                    ),
                )
                raw_candidates.append((item, best_rule, matched_str))

        # Generate final Finding objects and masked replacements
        findings: List[Finding] = []
        for item, rule, raw_match_val in raw_candidates:
            # Contextual escalation (FR-4.3)
            final_severity = adjust_severity_for_context(
                base_severity=rule.severity,
                field_name=item.key_name,
                location_path=item.location,
                parent_context=item.parent_context,
            )

            # Masked value generation (FR-5.1, FR-5.2)
            masked = mask_value(
                raw_match_val,
                finding_type=rule.finding_type,
                rule_id=rule.rule_id,
                style=self.masking_style,
            )
            raw_to_masked_map[raw_match_val] = masked

            # Advice & standard mapping (FR-6.1, FR-6.2)
            advice = get_advice_for_rule(
                rule_id=rule.rule_id,
                custom_risk=rule.risk,
                custom_rec=rule.recommendation,
                custom_standards=rule.standards,
            )

            fid = f"FND-{len(findings) + 1:04d}"
            finding = Finding(
                finding_id=fid,
                file_name=loaded.source_name,
                location=item.location,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                finding_type=rule.finding_type,
                severity=final_severity,
                confidence=rule.confidence,
                masked_value=masked,
                risk=advice["risk"],
                recommendation=advice["recommendation"],
                standards=advice.get("standards", []),
            )
            findings.append(finding)

        # Generate sanitized copy of the full payload (FR-5.4)
        sanitized_payload = mask_payload(loaded.content, raw_to_masked_map)

        return findings, sanitized_payload

    def scan_multiple(
        self,
        items: List[LoadedItem],
    ) -> Tuple[List[Finding], Dict[str, str]]:
        """Scans multiple loaded items, combining findings and masked copies."""
        all_findings: List[Finding] = []
        masked_copies: Dict[str, str] = {}

        for item in items:
            fnds, sanitized = self.scan_item(item)
            all_findings.extend(fnds)
            masked_copies[item.source_name] = sanitized

        return all_findings, masked_copies
