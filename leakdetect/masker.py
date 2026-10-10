"""
Masker Module for Sensitive Data Leak Detector.
Implements type-specific masking, multiple masking styles (partial, full, hash-based),
and whole-payload sanitization. Guarantees raw sensitive values never leak (FR-5.1, NFR-1).
"""

from __future__ import annotations
import hashlib
import re
from enum import Enum
from typing import Any, Dict, List, Optional


class MaskingStyle(str, Enum):
    PARTIAL = "partial"
    FULL = "full"
    HASH = "hash"


def sha256_hash_mask(value: str) -> str:
    """Generates a secure shortened cryptographic hash representation."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"[sha256:{digest}]"


def full_mask(value: str) -> str:
    """Replaces value with asterisk sequence preserving approximate visual boundary."""
    length = max(8, min(len(value), 32))
    return "*" * length


def mask_email(email_str: str) -> str:
    """Emails keep the first letter and domain ending (e.g. j***@e*****.com)."""
    if "@" not in email_str:
        return email_str[:1] + "****" if email_str else "****"

    try:
        local, domain = email_str.split("@", 1)
        masked_local = (local[0] + "***") if local else "***"

        if "." in domain:
            dom_name, dom_tld = domain.rsplit(".", 1)
            masked_dom = (dom_name[0] + "*" * min(5, max(3, len(dom_name) - 1))) if dom_name else "***"
            return f"{masked_local}@{masked_dom}.{dom_tld}"
        else:
            return f"{masked_local}@{domain[:1]}***"
    except Exception:
        return email_str[:1] + "***@***.***"


def mask_phone(phone_str: str) -> str:
    """Phone numbers keep only the last few digits (e.g. +91-*****-**210)."""
    digits_only = re.sub(r"\D", "", phone_str)
    if len(digits_only) < 4:
        return "******"

    last_digits = digits_only[-3:] if len(digits_only) >= 3 else digits_only
    prefix = ""
    if "+91" in phone_str or phone_str.strip().startswith("91") and len(digits_only) > 10:
        prefix = "+91-"
    elif phone_str.strip().startswith("+"):
        prefix = "+*-"

    return f"{prefix}*****-**{last_digits}"


def mask_card(card_str: str) -> str:
    """Credit cards show only the last four digits (e.g. ****-****-****-1111)."""
    digits = re.sub(r"\D", "", card_str)
    last_four = digits[-4:] if len(digits) >= 4 else "0000"
    return f"****-****-****-{last_four}"


def mask_secret_or_token(secret_str: str) -> str:
    """Secrets/tokens keep the first 2 to 4 characters followed by ****."""
    cleaned = secret_str.strip()
    if cleaned.startswith("Bearer "):
        token_part = cleaned[7:].strip()
        return f"Bearer {token_part[:4]}****"
    if len(cleaned) <= 4:
        return cleaned[:1] + "****" if cleaned else "****"
    prefix_len = min(4, max(2, len(cleaned) // 4))
    return f"{cleaned[:prefix_len]}****"


def mask_aadhaar(aadhaar_str: str) -> str:
    """Indian Aadhaar keeps only the last 4 digits (****-****-1234)."""
    digits = re.sub(r"\D", "", aadhaar_str)
    last_four = digits[-4:] if len(digits) >= 4 else "****"
    return f"****-****-{last_four}"


def mask_pan(pan_str: str) -> str:
    """Indian PAN cards keep first two and last letter (e.g. AB****F)."""
    cleaned = pan_str.strip()
    if len(cleaned) == 10:
        return f"{cleaned[:2]}*****{cleaned[-1]}"
    return mask_secret_or_token(pan_str)


def mask_db_conn(conn_str: str) -> str:
    """Masks credentials in database URIs (e.g. mongodb://****:****@host)."""
    # Replace user:pass pattern inside URI
    masked = re.sub(r"://([^:@\s]+):([^@\s]+)@", r"://****:****@", conn_str)
    return masked if masked != conn_str else conn_str[:12] + "****"


def mask_ip(ip_str: str) -> str:
    """Masks private IP host octets (e.g. 192.168.***.***)."""
    parts = ip_str.strip().split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return ip_str[:4] + "****"


def mask_value(
    value: str,
    finding_type: str = "Secret",
    rule_id: str = "",
    style: str = MaskingStyle.PARTIAL.value,
) -> str:
    """Main masking router according to rule type and user style preference."""
    if not value:
        return "****"

    if style == MaskingStyle.FULL.value or style == "full":
        return full_mask(value)
    elif style == MaskingStyle.HASH.value or style == "hash":
        return sha256_hash_mask(value)

    # Default: Type-specific partial masking (FR-5.2)
    rule_upper = rule_id.upper()
    type_upper = finding_type.upper()

    if "DBCONN" in rule_upper:
        return mask_db_conn(value)
    elif "CARD" in rule_upper or "FINANCIAL" in type_upper:
        return mask_card(value)
    elif "EMAIL" in rule_upper:
        return mask_email(value)
    elif "PHONE" in rule_upper:
        return mask_phone(value)
    elif "AADHAAR" in rule_upper:
        return mask_aadhaar(value)
    elif "PAN" in rule_upper:
        return mask_pan(value)
    elif "IP" in rule_upper:
        return mask_ip(value)
    elif "@" in value and "://" not in value:
        return mask_email(value)
    else:
        return mask_secret_or_token(value)


def mask_payload(
    original_text: str,
    raw_to_masked_map: Dict[str, str],
) -> str:
    """Produces a sanitized copy of the full payload text with every finding replaced (FR-5.4).
    Sorts keys by length descending to prevent substring collisions.
    """
    sanitized = original_text
    sorted_targets = sorted(raw_to_masked_map.keys(), key=len, reverse=True)

    for raw_val in sorted_targets:
        if raw_val and len(raw_val) >= 3:
            masked_val = raw_to_masked_map[raw_val]
            sanitized = sanitized.replace(raw_val, masked_val)

    return sanitized
