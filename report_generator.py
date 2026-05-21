"""Incident report generation and persistence."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from crypto_utils import calculate_sha256, generate_hmac_signature


REPORTS_DIR = Path(__file__).parent / "reports"


def ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _safe_slug(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "_" for char in value).strip("_")[:48] or "alert"


def build_report_record(
    alert_text: str,
    model: str,
    rule_analysis: dict[str, Any],
    llm_analysis: dict[str, Any],
    mitre_mapping: list[dict[str, Any]],
    ioc_enrichment: dict[str, Any] | None = None,
    confidence_comparison: dict[str, Any] | None = None,
    incident_timeline: list[dict[str, Any]] | None = None,
    analyst_decision: str = "Pending Analyst Review",
) -> dict[str, Any]:
    """Create the canonical report object saved as JSON and rendered as TXT."""
    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "project": "Bank SOC Assistant: Local LLM-Based Security Alert Analyzer",
        "llm_provider": "Ollama local API",
        "model": model,
        "alert_text": alert_text,
        "rule_based_pre_analysis": rule_analysis,
        "ioc_enrichment": ioc_enrichment or {},
        "confidence_comparison": confidence_comparison or {},
        "llm_analysis": llm_analysis,
        "mitre_attack_mapping": mitre_mapping,
        "incident_timeline": incident_timeline or [],
        "analyst_decision": analyst_decision,
    }


def render_text_report(report: dict[str, Any]) -> str:
    analysis = report["llm_analysis"]
    lines = [
        "BANK SOC INCIDENT REPORT",
        "=" * 80,
        f"Generated At: {report['generated_at']}",
        f"Model: {report['model']} via {report['llm_provider']}",
        "",
        "Alert Summary",
        "-" * 80,
        analysis["alert_summary"],
        "",
        "Classification",
        "-" * 80,
        f"Attack Type: {analysis['attack_type']}",
        f"Severity: {analysis['severity']}",
        f"Confidence Score: {analysis['confidence_score']}/100",
        f"False Positive Possibility: {analysis['false_positive_possibility']}",
        f"Analyst Decision: {report.get('analyst_decision', 'Pending Analyst Review')}",
        "",
        "Confidence Comparison",
        "-" * 80,
        f"Rule Confidence: {report.get('confidence_comparison', {}).get('rule_confidence_score', 'N/A')}",
        f"LLM Confidence: {analysis['confidence_score']}/100",
        f"IOC Risk: {report.get('ioc_enrichment', {}).get('overall_ioc_risk_level', 'N/A')}",
        "",
        "Indicators of Compromise",
        "-" * 80,
        *[f"- {ioc}" for ioc in analysis["indicators_of_compromise"]],
        "",
        "IOC Enrichment",
        "-" * 80,
    ]

    enrichment_items = report.get("ioc_enrichment", {}).get("items", [])
    if enrichment_items:
        for item in enrichment_items:
            lines.append(
                f"- {item['indicator']} ({item['type']}): "
                f"{item['risk_level']} risk, score {item['risk_score']}/100"
            )
            for note in item.get("notes", []):
                lines.append(f"  Note: {note}")
    else:
        lines.append("- No indicators available for enrichment.")

    lines.extend(
        [
            "",
        "Affected Assets",
        "-" * 80,
        *[f"- {asset}" for asset in analysis["affected_assets"]],
        "",
        "Bank Business Impact",
        "-" * 80,
        analysis["business_impact_for_bank"],
        "",
        "Technical Explanation",
        "-" * 80,
        analysis["technical_explanation"],
        "",
        "Recommended Remediation Steps",
        "-" * 80,
        *[f"- {step}" for step in analysis["recommended_remediation_steps"]],
        "",
        "Incident Timeline",
        "-" * 80,
        ]
    )

    for event in report.get("incident_timeline", []):
        lines.append(f"- {event.get('stage', 'Event')}: {event.get('description', '')}")

    lines.extend(
        [
        "",
        "MITRE ATT&CK Mapping",
        "-" * 80,
        ]
    )

    for item in report["mitre_attack_mapping"]:
        lines.append(
            f"- {item['technique_id']} {item['technique_name']} | "
            f"Tactic: {item['tactic']} | {item['description']}"
        )

    lines.extend(
        [
            "",
            "Final Incident Report",
            "-" * 80,
            analysis["final_incident_report"],
            "",
            "Original Alert",
            "-" * 80,
            report["alert_text"],
        ]
    )
    return "\n".join(lines)


def save_report(report: dict[str, Any]) -> dict[str, str]:
    """Save JSON and TXT reports, then write integrity metadata."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    slug = _safe_slug(report["llm_analysis"].get("attack_type", "bank_soc_alert"))
    base_name = f"{timestamp}_{slug}"

    json_path = reports_dir / f"{base_name}.json"
    txt_path = reports_dir / f"{base_name}.txt"
    meta_path = reports_dir / f"{base_name}.integrity.json"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    txt_path.write_text(render_text_report(report), encoding="utf-8")

    json_hash = calculate_sha256(json_path)
    txt_hash = calculate_sha256(txt_path)
    metadata = {
        "json_report": json_path.name,
        "txt_report": txt_path.name,
        "json_sha256": json_hash,
        "txt_sha256": txt_hash,
        "json_hmac_signature": generate_hmac_signature(json_hash),
        "txt_hmac_signature": generate_hmac_signature(txt_hash),
        "created_at": report["generated_at"],
    }
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return {
        "json_path": str(json_path),
        "txt_path": str(txt_path),
        "meta_path": str(meta_path),
        "json_hash": json_hash,
        "txt_hash": txt_hash,
        "json_hmac_signature": metadata["json_hmac_signature"],
        "txt_hmac_signature": metadata["txt_hmac_signature"],
    }


def list_integrity_metadata() -> list[Path]:
    ensure_reports_dir()
    return sorted(REPORTS_DIR.glob("*.integrity.json"), reverse=True)


def load_report_history() -> list[dict[str, Any]]:
    ensure_reports_dir()
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json"), reverse=True):
        if path.name.endswith(".integrity.json"):
            continue
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return reports
