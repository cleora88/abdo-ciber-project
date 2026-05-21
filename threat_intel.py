"""Privacy-conscious IOC enrichment for the bank SOC assistant.

The enrichment is local and heuristic by default. It does not send the full
bank alert to any online service, which keeps the LLM workflow privacy-safe.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_DOMAIN_TERMS = [
    "secure",
    "login",
    "verify",
    "update",
    "bank",
    "payroll",
    "benefits",
    "cloud",
    "sync",
]

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Informational"


def _extract_domain(url_or_domain: str) -> str:
    value = url_or_domain.strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return parsed.netloc.lower() or parsed.path.lower()


def enrich_ip(ip_value: str) -> dict:
    score = 0
    notes = []
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return {
            "indicator": ip_value,
            "type": "ip",
            "risk_score": 10,
            "risk_level": "Low",
            "notes": ["Invalid IP format. Verify manually."],
            "lookup_links": [],
        }

    is_documentation = any(ip in network for network in DOCUMENTATION_NETWORKS)

    if ip.is_private:
        notes.append("Private/internal address. Useful for asset scoping.")
        score += 10
    elif ip.is_loopback:
        notes.append("Loopback address. Usually not externally malicious.")
        score += 5
    elif ip.is_reserved or is_documentation:
        notes.append("Reserved or documentation range. Good for demo data, verify in real cases.")
        score += 20
    else:
        notes.append("Public IP address. Check firewall, proxy, and threat intelligence context.")
        score += 45

    if ip.is_global:
        score += 15
        notes.append("Globally routable IP observed in the alert.")

    return {
        "indicator": ip_value,
        "type": "ip",
        "risk_score": min(score, 100),
        "risk_level": _risk_level(score),
        "notes": notes,
        "lookup_links": [
            f"https://www.virustotal.com/gui/ip-address/{ip_value}",
            f"https://talosintelligence.com/reputation_center/lookup?search={ip_value}",
        ],
    }


def enrich_url(url_value: str) -> dict:
    domain = _extract_domain(url_value)
    score = 20
    notes = [f"Extracted domain: {domain}"]

    matched_terms = [term for term in SUSPICIOUS_DOMAIN_TERMS if term in domain]
    if matched_terms:
        score += min(45, len(matched_terms) * 10)
        notes.append(f"Domain contains bank/phishing-like terms: {', '.join(matched_terms)}")

    if domain.endswith(".example.com") or domain.endswith(".example.net") or domain.endswith(".example.org"):
        notes.append("Example domain used for safe demo data.")
        score = min(score, 35)

    if "http://" in url_value.lower():
        score += 15
        notes.append("Plain HTTP URL observed. This is riskier for credential or payload delivery.")

    return {
        "indicator": url_value,
        "type": "url",
        "risk_score": min(score, 100),
        "risk_level": _risk_level(score),
        "notes": notes,
        "lookup_links": [
            f"https://www.virustotal.com/gui/domain/{domain}",
            f"https://urlscan.io/search/#{domain}",
        ],
    }


def enrich_email(email_value: str) -> dict:
    domain = email_value.split("@")[-1].lower() if "@" in email_value else ""
    score = 25
    notes = [f"Sender or recipient domain: {domain}"] if domain else ["Email format needs review."]

    matched_terms = [term for term in SUSPICIOUS_DOMAIN_TERMS if term in domain]
    if matched_terms:
        score += min(35, len(matched_terms) * 8)
        notes.append(f"Domain contains terms often abused in phishing: {', '.join(matched_terms)}")

    if domain and not domain.endswith(("bank.local", "bank.example")):
        score += 10
        notes.append("External email domain. Confirm SPF, DKIM, DMARC, and sender reputation.")

    return {
        "indicator": email_value,
        "type": "email",
        "risk_score": min(score, 100),
        "risk_level": _risk_level(score),
        "notes": notes,
        "lookup_links": [f"https://www.virustotal.com/gui/domain/{domain}"] if domain else [],
    }


def enrich_hash(hash_value: str) -> dict:
    length = len(hash_value)
    hash_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(length, "Unknown hash")
    score = 50 if hash_type != "Unknown hash" else 25
    notes = [f"Detected {hash_type}. Check endpoint telemetry and malware reputation."]

    if hash_type in {"MD5", "SHA-1"}:
        notes.append("Older hash type. Still useful for IOC matching, but SHA-256 is preferred.")

    return {
        "indicator": hash_value,
        "type": "hash",
        "risk_score": score,
        "risk_level": _risk_level(score),
        "notes": notes,
        "lookup_links": [f"https://www.virustotal.com/gui/file/{hash_value}"],
    }


def enrich_indicators(indicators: dict) -> dict:
    """Enrich extracted IOCs without sending the full alert anywhere."""
    enriched = []
    for ip_value in indicators.get("ips", []):
        enriched.append(enrich_ip(ip_value))
    for url_value in indicators.get("urls", []):
        enriched.append(enrich_url(url_value))
    for email_value in indicators.get("emails", []):
        enriched.append(enrich_email(email_value))
    for hash_value in indicators.get("hashes", []):
        enriched.append(enrich_hash(hash_value))

    max_score = max([item["risk_score"] for item in enriched], default=0)
    return {
        "mode": "Local heuristic IOC enrichment",
        "privacy_note": "Only extracted indicators are enriched. Full bank alerts are not sent online.",
        "overall_ioc_risk_score": max_score,
        "overall_ioc_risk_level": _risk_level(max_score),
        "items": enriched,
    }


def calculate_rule_confidence(rule_analysis: dict) -> dict:
    categories = rule_analysis.get("detected_categories", [])
    indicators = rule_analysis.get("indicators", {})
    ioc_count = sum(len(indicators.get(name, [])) for name in ["ips", "urls", "emails", "hashes"])
    score = min(100, 20 + len(categories) * 15 + ioc_count * 8)
    if not categories:
        score = min(score, 30)
    return {
        "rule_confidence_score": score,
        "rule_confidence_level": _risk_level(score),
        "basis": f"{len(categories)} detected rule categories and {ioc_count} extracted indicators.",
    }
