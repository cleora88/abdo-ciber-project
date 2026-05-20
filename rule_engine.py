"""Rule-based pre-analysis for bank SOC alerts before LLM enrichment."""

from __future__ import annotations

import re
from typing import Any


SQLI_PATTERNS = [
    r"(?i)\bunion\b\s+\bselect\b",
    r"(?i)\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\binformation_schema\b",
    r"(?i)--",
    r"(?i)\bsleep\s*\(",
]

XSS_PATTERNS = [
    r"(?i)<script\b",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)<img[^>]+src",
]

PHISHING_PATTERNS = [
    r"(?i)\burgent\b",
    r"(?i)\bpassword reset\b",
    r"(?i)\bverify your account\b",
    r"(?i)\bcredential\b",
    r"(?i)\blogin portal\b",
    r"(?i)\bwire transfer\b",
    r"(?i)\battachment\b",
]

BRUTE_FORCE_PATTERNS = [
    r"(?i)\bfailed logins?\b",
    r"(?i)\bmultiple failed\b",
    r"(?i)\bpassword spraying\b",
    r"(?i)\bbrute[- ]force\b",
    r"(?i)\baccount lockout\b",
]

MALWARE_PATTERNS = [
    r"(?i)\bmalware\b",
    r"(?i)\btrojan\b",
    r"(?i)\bransomware\b",
    r"(?i)\bquarantined\b",
    r"(?i)\bendpoint detection\b",
    r"(?i)\bpowershell\b",
]

EXFIL_PATTERNS = [
    r"(?i)\bdata exfiltration\b",
    r"(?i)\bunusual outbound\b",
    r"(?i)\blarge outbound\b",
    r"(?i)\bcloud storage\b",
    r"(?i)\bexternal ftp\b",
    r"(?i)\buploaded\b",
]

ATM_PATTERNS = [
    r"(?i)\batm\b",
    r"(?i)\bcash withdrawal\b",
    r"(?i)\bcard-present\b",
    r"(?i)\bcash-out\b",
]

IP_PATTERN = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
URL_PATTERN = r"https?://[^\s\"'<>]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s\"'<>]*)?"
EMAIL_PATTERN = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
HASH_PATTERN = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"


def _matches(patterns: list[str], text: str) -> list[str]:
    found = []
    for pattern in patterns:
        if re.search(pattern, text):
            found.append(pattern)
    return found


def _unique_regex(pattern: str, text: str) -> list[str]:
    return sorted(set(re.findall(pattern, text)))


def analyze_alert(alert_text: str) -> dict[str, Any]:
    """Perform deterministic pre-analysis and IOC extraction."""
    text = alert_text or ""
    categories: list[str] = []
    findings: list[str] = []

    checks = [
        ("sql_injection", "SQL injection indicators detected", SQLI_PATTERNS),
        ("xss", "XSS payload indicators detected", XSS_PATTERNS),
        ("phishing", "Phishing/social engineering indicators detected", PHISHING_PATTERNS),
        ("brute_force", "Brute-force or credential attack indicators detected", BRUTE_FORCE_PATTERNS),
        ("malware", "Malware or endpoint compromise indicators detected", MALWARE_PATTERNS),
        ("data_exfiltration", "Possible data exfiltration indicators detected", EXFIL_PATTERNS),
        ("atm_fraud", "Suspicious ATM transaction indicators detected", ATM_PATTERNS),
    ]

    matched_rules: dict[str, list[str]] = {}
    for category, finding, patterns in checks:
        matched = _matches(patterns, text)
        if matched:
            categories.append(category)
            findings.append(finding)
            matched_rules[category] = matched

    iocs = {
        "ips": _unique_regex(IP_PATTERN, text),
        "urls": _unique_regex(URL_PATTERN, text),
        "emails": _unique_regex(EMAIL_PATTERN, text),
        "hashes": _unique_regex(HASH_PATTERN, text),
    }

    severity_hint = "Low"
    if {"sql_injection", "data_exfiltration", "malware"} & set(categories):
        severity_hint = "High"
    if "brute_force" in categories or "phishing" in categories:
        severity_hint = "Medium" if severity_hint == "Low" else severity_hint
    if "data_exfiltration" in categories and (iocs["ips"] or iocs["urls"]):
        severity_hint = "Critical"

    return {
        "detected_categories": categories,
        "findings": findings or ["No high-confidence rule match. LLM/manual review still required."],
        "matched_rules": matched_rules,
        "indicators": iocs,
        "severity_hint": severity_hint,
    }
