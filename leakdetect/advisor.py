"""
Advisor Module for Sensitive Data Leak Detector.
Provides contextual risk explanations, remediation recommendations,
compliance mappings (OWASP, GDPR, PCI-DSS), and executive advice rollups.
"""

from __future__ import annotations
from typing import Any, Dict, List


DEFAULT_ADVISORY_MAP: Dict[str, Dict[str, Any]] = {
    "R-EMAIL": {
        "risk": "Exposes private user email addresses. Enables spear phishing, account enumeration, and data correlation across breaches.",
        "recommendation": "Return only the fields the client requires. Do not expose personal email in public API responses.",
        "standards": ["GDPR Article 32 (Security of Processing)", "OWASP API3:2023 Broken Object Property Level Authorization"],
    },
    "R-PHONE": {
        "risk": "Exposes personal mobile or telephone numbers. Enables SMS phishing (smishing), SIM swapping reconnaissance, and harassment.",
        "recommendation": "Leave the phone number out or mask it (+91-*****-**210) before returning payload to unauthorized clients.",
        "standards": ["GDPR Article 32", "OWASP API3:2023 Broken Object Property Level Authorization"],
    },
    "R-PASSWORD": {
        "risk": "Plaintext passwords or password hashes directly expose user credentials, leading to immediate account compromise and lateral movement.",
        "recommendation": "Never send passwords or hashes in a response under any circumstances. Strip password fields at the serialization layer.",
        "standards": ["OWASP API2:2023 Broken Authentication", "PCI-DSS Requirement 8.3", "CWE-259 Hard-coded Password"],
    },
    "R-APIKEY": {
        "risk": "Exposed API keys allow adversaries to make unauthorized API calls, exhaust API quotas, access backend databases, and impersonate the app.",
        "recommendation": "Rotate the exposed API key immediately. Store API keys in environment variables or a secrets manager (e.g. AWS Secrets Manager, Vault).",
        "standards": ["OWASP API8:2023 Security Misconfiguration", "CWE-798 Hard-coded Credentials"],
    },
    "R-JWT": {
        "risk": "Exposed JSON Web Tokens can be used by an attacker to impersonate the token subject, bypass authorization, and hijack active sessions.",
        "recommendation": "Do not echo tokens back in responses unnecessarily. Rotate signing secrets if compromised, and implement short token expiry with revocation.",
        "standards": ["OWASP API2:2023 Broken Authentication", "RFC 7519"],
    },
    "R-BEARER": {
        "risk": "Bearer authorization tokens grant full bearer capabilities to any holder without cryptographic proof of possession.",
        "recommendation": "Do not echo Authorization headers or bearer tokens back in response payloads. Rotate token if leaked.",
        "standards": ["OWASP API2:2023 Broken Authentication", "RFC 6750"],
    },
    "R-AWS": {
        "risk": "Exposed AWS access keys grant programmatic control over cloud infrastructure, S3 buckets, compute instances, and billing.",
        "recommendation": "Immediately deactivate and delete the compromised access key in AWS IAM. Review CloudTrail audit logs for suspicious operations.",
        "standards": ["OWASP API8:2023 Security Misconfiguration", "CIS AWS Foundations Benchmark"],
    },
    "R-PRIVKEY": {
        "risk": "Private cryptographic keys compromise transport security (TLS), SSH server access, or code signing verification completely.",
        "recommendation": "Remove private keys immediately. Revoke and reissue associated SSL/TLS certificates or SSH authorized keys.",
        "standards": ["OWASP API8:2023 Security Misconfiguration", "PCI-DSS Requirement 3.5"],
    },
    "R-CARD": {
        "risk": "Cardholder PAN leakage facilitates fraudulent transactions, financial identity theft, and severe regulatory fines under PCI-DSS.",
        "recommendation": "Never send full PAN in API responses. Truncate to last 4 digits (****-****-****-1111) or utilize tokenization gateways (Stripe, Adyen).",
        "standards": ["PCI-DSS Requirement 3.4", "OWASP API3:2023 Broken Object Property Level Authorization"],
    },
    "R-AADHAAR": {
        "risk": "Aadhaar numbers uniquely identify Indian citizens. Leaks violate Indian statutory privacy regulations and facilitate fraudulent identity documentation.",
        "recommendation": "Mask Aadhaar numbers to show only the last 4 digits (****-****-1234) as mandated by UIDAI, or drop the attribute.",
        "standards": ["Aadhaar Act 2016", "Digital Personal Data Protection Act (DPDPA 2023)"],
    },
    "R-PAN": {
        "risk": "Indian Permanent Account Numbers are tied to income tax and banking identities, enabling fraud in credit and loan applications.",
        "recommendation": "Redact or mask PAN values in API responses unless specifically needed for authorized statutory compliance.",
        "standards": ["Indian DPDPA 2023", "IT Act Section 43A"],
    },
    "R-DBCONN": {
        "risk": "Database connection strings expose internal database hosts, port mappings, and often cleartext administrative passwords.",
        "recommendation": "Ensure connection strings reside in backend environment variables and are never leaked in error logs or responses.",
        "standards": ["OWASP API8:2023 Security Misconfiguration", "CWE-200 Information Exposure"],
    },
    "R-IP": {
        "risk": "Internal IP addresses reveal private network subnet topologies, assisting attackers in pivoting once perimeter defenses are breached.",
        "recommendation": "Strip internal IP addresses and internal infrastructure details before serving responses outside the firewall.",
        "standards": ["RFC 1918 Private Address Allocation", "OWASP API8:2023 Security Misconfiguration"],
    },
    "R-PATH": {
        "risk": "Server file paths and stack traces expose directory hierarchies, operating system details, and library versions to attackers.",
        "recommendation": "Disable verbose error tracebacks in production. Implement structured error schemas returning friendly error codes.",
        "standards": ["OWASP API8:2023 Security Misconfiguration", "CWE-209 Stack Trace Exposure"],
    },
    "R-NAME": {
        "risk": "Personal names can identify individuals and constitute personal data under privacy legislation when linked to other attributes.",
        "recommendation": "Ensure personal names are shared only on authorized endpoints with appropriate consent.",
        "standards": ["GDPR Article 4", "DPDPA 2023"],
    },
}


def get_advice_for_rule(rule_id: str, custom_risk: str = "", custom_rec: str = "", custom_standards: List[str] = None) -> Dict[str, Any]:
    """Retrieves or synthesizes risk and remediation advice for a given rule ID."""
    if custom_risk and custom_rec:
        return {
            "risk": custom_risk,
            "recommendation": custom_rec,
            "standards": custom_standards or ["OWASP API Security Top 10"],
        }

    default_info = DEFAULT_ADVISORY_MAP.get(rule_id)
    if default_info:
        return {
            "risk": custom_risk or default_info["risk"],
            "recommendation": custom_rec or default_info["recommendation"],
            "standards": custom_standards or default_info.get("standards", []),
        }

    return {
        "risk": custom_risk or "Sensitive internal information is exposed in the API response, violating the principle of least privilege.",
        "recommendation": custom_rec or "Review API schema, apply field filtering, and avoid echoing sensitive properties back to clients.",
        "standards": custom_standards or ["OWASP API3:2023 Broken Object Property Level Authorization"],
    }


def summarize_top_recommendations(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Synthesizes top recommendations grouped and prioritized by severity."""
    recs: List[Dict[str, str]] = []
    seen_rules = set()

    # Priority order: Critical, High, Medium, Low
    priority_order = ["Critical", "High", "Medium", "Low"]
    for prio in priority_order:
        for f in findings:
            if f.get("severity") == prio:
                rule_id = f.get("rule_id", "UNKNOWN")
                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    recs.append({
                        "priority": prio,
                        "title": f.get("rule_name", rule_id),
                        "recommendation": f.get("recommendation", "Sanitize API response"),
                        "risk": f.get("risk", "Data exposure risk"),
                    })

    return recs
