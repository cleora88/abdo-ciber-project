"""Simple MITRE ATT&CK mapping for common bank SOC alert categories."""

from __future__ import annotations


MITRE_MAPPINGS = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated attempts to guess or reuse credentials.",
    },
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Deceptive messages used to obtain credentials or deliver malware.",
    },
    "sql_injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Web application exploitation against public banking services.",
    },
    "xss": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Client-side script injection against a public web application.",
    },
    "malware": {
        "technique_id": "Execution / Malware",
        "technique_name": "Malware Execution",
        "tactic": "Execution",
        "description": "Suspicious or malicious code execution on an endpoint.",
    },
    "data_exfiltration": {
        "technique_id": "Exfiltration tactic",
        "technique_name": "Data Exfiltration",
        "tactic": "Exfiltration",
        "description": "Unauthorized transfer of sensitive bank data outside the network.",
    },
    "atm_fraud": {
        "technique_id": "N/A",
        "technique_name": "Suspicious ATM Activity",
        "tactic": "Fraud / Impact",
        "description": "Potential account takeover, card compromise, or cash-out pattern.",
    },
}


def map_to_mitre(detected_categories: list[str], llm_attack_type: str = "") -> list[dict]:
    """Return MITRE mappings based on rule findings and the LLM attack label."""
    normalized_attack = llm_attack_type.lower()
    categories = set(detected_categories)

    if "brute" in normalized_attack:
        categories.add("brute_force")
    if "phish" in normalized_attack:
        categories.add("phishing")
    if "sql" in normalized_attack or "injection" in normalized_attack:
        categories.add("sql_injection")
    if "xss" in normalized_attack or "script" in normalized_attack:
        categories.add("xss")
    if "malware" in normalized_attack or "trojan" in normalized_attack:
        categories.add("malware")
    if "exfil" in normalized_attack or "data" in normalized_attack:
        categories.add("data_exfiltration")
    if "atm" in normalized_attack:
        categories.add("atm_fraud")

    mappings = [MITRE_MAPPINGS[name] for name in sorted(categories) if name in MITRE_MAPPINGS]
    return mappings or [
        {
            "technique_id": "N/A",
            "technique_name": "No direct mapping",
            "tactic": "Unknown",
            "description": "The alert needs manual analyst review for mapping.",
        }
    ]
