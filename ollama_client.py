"""Local Ollama client for bank SOC alert analysis."""

from __future__ import annotations

import json
import re
from typing import Any

import requests


OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
REQUIRED_FIELDS = [
    "alert_summary",
    "attack_type",
    "severity",
    "confidence_score",
    "indicators_of_compromise",
    "affected_assets",
    "business_impact_for_bank",
    "technical_explanation",
    "recommended_remediation_steps",
    "false_positive_possibility",
    "final_incident_report",
]
ALLOWED_SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}


class OllamaError(RuntimeError):
    """Raised when the local Ollama service cannot provide a valid analysis."""


def _extract_json(text: str) -> dict[str, Any]:
    """Parse strict JSON or extract the first JSON object from a model response."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise OllamaError("The model did not return a JSON object.") from None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise OllamaError(f"Invalid LLM JSON response: {exc}") from exc


def _validate_analysis(data: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if missing:
        raise OllamaError(f"LLM JSON response is missing fields: {', '.join(missing)}")

    if data["severity"] not in ALLOWED_SEVERITIES:
        data["severity"] = "Medium"

    try:
        score = int(data["confidence_score"])
    except (TypeError, ValueError):
        score = 50
    data["confidence_score"] = max(0, min(100, score))

    for field in ["indicators_of_compromise", "affected_assets", "recommended_remediation_steps"]:
        if not isinstance(data[field], list):
            data[field] = [str(data[field])]

    return data


def build_soc_prompt(alert_text: str, rule_analysis: dict[str, Any]) -> str:
    """Build a concise prompt that forces a structured bank SOC JSON response."""
    return f"""
You are a senior cybersecurity analyst in a bank Security Operations Center.
Analyze this bank security alert using the rule-based pre-analysis as supporting context.

Return ONLY valid JSON. Do not include markdown, comments, or extra text.

Required JSON fields:
- alert_summary: string
- attack_type: string
- severity: one of Informational, Low, Medium, High, Critical
- confidence_score: integer from 0 to 100
- indicators_of_compromise: array of strings
- affected_assets: array of strings
- business_impact_for_bank: string
- technical_explanation: string
- recommended_remediation_steps: array of strings
- false_positive_possibility: string
- final_incident_report: string

Bank SOC alert:
{alert_text}

Rule-based pre-analysis:
{json.dumps(rule_analysis, indent=2)}
""".strip()


def analyze_with_ollama(model: str, alert_text: str, rule_analysis: dict[str, Any]) -> dict[str, Any]:
    """Send the alert to a local Ollama model and return validated JSON analysis."""
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": "You produce strict JSON for bank SOC incident analysis.",
            },
            {"role": "user", "content": build_soc_prompt(alert_text, rule_analysis)},
        ],
        "options": {"temperature": 0.2},
    }

    try:
        response = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=90)
    except requests.ConnectionError as exc:
        raise OllamaError(
            "Ollama is not running. Start it locally and confirm http://localhost:11434 is reachable."
        ) from exc
    except requests.Timeout as exc:
        raise OllamaError("Ollama request timed out. Try a smaller model or shorter alert.") from exc

    if response.status_code == 404:
        raise OllamaError(f"Model '{model}' is not installed. Run: ollama pull {model}")
    if response.status_code >= 400:
        raise OllamaError(f"Ollama returned HTTP {response.status_code}: {response.text[:300]}")

    body = response.json()
    content = body.get("message", {}).get("content", "")
    if not content:
        raise OllamaError("Ollama returned an empty response.")

    return _validate_analysis(_extract_json(content))
