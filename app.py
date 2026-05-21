"""Streamlit UI for the Bank SOC Assistant project."""

from __future__ import annotations

import html
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from crypto_utils import verify_report_integrity
from mitre_mapper import map_to_mitre
from ollama_client import OllamaError, analyze_with_ollama
from report_generator import (
    REPORTS_DIR,
    build_report_record,
    list_integrity_metadata,
    load_report_history,
    save_report,
)
from rule_engine import analyze_alert
from threat_intel import calculate_rule_confidence, enrich_indicators


BASE_DIR = Path(__file__).parent
SAMPLES_PATH = BASE_DIR / "sample_alerts.json"


st.set_page_config(
    page_title="Bank SOC Assistant",
    page_icon="BANK",
    layout="wide",
)


def apply_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bank-navy: #10233f;
            --bank-gold: #c79a3a;
            --bank-green: #1f7a5b;
            --bank-text: #142033;
            --bank-muted: #5d6b7c;
            --bank-surface: #ffffff;
            --bank-border: #d8e0ec;
        }
        .stApp {
            background: #f5f7fb;
            color: var(--bank-text);
        }
        .stApp h1,
        .stApp h2,
        .stApp h3,
        .stApp h4,
        .stApp h5,
        .stApp h6,
        .stApp p,
        .stApp label,
        .stApp span,
        .stApp div {
            color: var(--bank-text);
        }
        [data-testid="stSidebar"] {
            background: var(--bank-navy);
            color: #ffffff;
        }
        [data-testid="stSidebar"] h1,
        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] span,
        [data-testid="stSidebar"] div {
            color: #ffffff;
        }
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"],
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] * {
            color: #c9d4e5;
        }
        [data-testid="stSidebar"] a {
            color: #8fc7ff;
        }
        [data-testid="stSelectbox"] label,
        [data-testid="stTextArea"] label,
        [data-testid="stTextInput"] label,
        [data-testid="stRadio"] label,
        [data-testid="stCaptionContainer"],
        [data-testid="stCaptionContainer"] * {
            color: var(--bank-muted);
            opacity: 1;
        }
        [data-testid="stRadio"] [role="radiogroup"] label span {
            color: var(--bank-text);
        }
        [data-baseweb="select"] > div,
        [data-baseweb="input"] input,
        textarea {
            background-color: var(--bank-surface);
            border-color: var(--bank-border);
            color: var(--bank-text);
        }
        [data-baseweb="select"] span,
        [data-baseweb="select"] svg,
        textarea,
        textarea::placeholder,
        input,
        input::placeholder {
            color: var(--bank-text);
            opacity: 1;
        }
        [data-testid="stSidebar"] [data-baseweb="select"] > div,
        [data-testid="stSidebar"] [data-baseweb="input"] input {
            background-color: #ffffff;
            border-color: #bfccdd;
            color: var(--bank-text);
        }
        [data-testid="stSidebar"] [data-baseweb="select"] div,
        [data-testid="stSidebar"] [data-baseweb="select"] input,
        [data-testid="stSidebar"] [data-baseweb="select"] [class*="singleValue"],
        [data-testid="stSidebar"] [data-baseweb="select"] [class*="placeholder"],
        [data-testid="stSidebar"] [data-baseweb="select"] span,
        [data-testid="stSidebar"] [data-baseweb="select"] svg,
        [data-testid="stSidebar"] [data-baseweb="input"] input,
        [data-testid="stSidebar"] [data-baseweb="input"] input::placeholder {
            color: var(--bank-text);
            opacity: 1;
        }
        [data-testid="stSidebar"] [data-baseweb="select"] svg path {
            fill: var(--bank-text);
        }
        [data-testid="stTabs"] [role="tab"] {
            color: var(--bank-muted);
        }
        [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
            color: #d9363e;
        }
        [data-testid="stMetric"],
        [data-testid="stAlert"],
        [data-testid="stJson"] {
            background-color: var(--bank-surface);
            color: var(--bank-text);
        }
        button[kind="primary"] {
            background-color: #d9363e;
            border-color: #d9363e;
            color: #ffffff;
        }
        button[kind="primary"] * {
            color: #ffffff;
        }
        .metric-card {
            background: #ffffff;
            border: 1px solid var(--bank-border);
            border-left: 5px solid var(--bank-gold);
            border-radius: 8px;
            padding: 16px;
        }
        .soc-banner {
            background: linear-gradient(90deg, #10233f 0%, #1f7a5b 100%);
            color: #ffffff;
            padding: 22px 26px;
            border-radius: 8px;
            margin-bottom: 18px;
        }
        .soc-banner h1 {
            margin: 0 0 6px 0;
            font-size: 30px;
            color: #ffffff;
        }
        .soc-banner p {
            margin: 0;
            font-size: 15px;
            color: #ffffff;
        }
        .light-json {
            background: #ffffff;
            border: 1px solid var(--bank-border);
            border-radius: 8px;
            color: var(--bank-text);
            font-family: Consolas, "Courier New", monospace;
            font-size: 14px;
            line-height: 1.5;
            max-height: 520px;
            overflow: auto;
            padding: 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .light-json * {
            color: var(--bank-text);
        }
        .severity-badge {
            border-radius: 999px;
            color: #ffffff;
            display: inline-block;
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0;
            margin: 4px 0 10px 0;
            padding: 6px 12px;
        }
        .severity-Informational { background: #6b7280; }
        .severity-Low { background: #2563eb; }
        .severity-Medium { background: #c28a12; }
        .severity-High { background: #d97706; }
        .severity-Critical { background: #dc2626; }
        .workflow-card {
            background: #ffffff;
            border: 1px solid var(--bank-border);
            border-radius: 8px;
            padding: 14px 16px;
            min-height: 94px;
        }
        .workflow-card strong {
            color: var(--bank-navy);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def show_light_json(data: object) -> None:
    """Render JSON in a readable light-mode block."""
    formatted = json.dumps(data, indent=2, ensure_ascii=False)
    st.markdown(f"<pre class='light-json'>{html.escape(formatted)}</pre>", unsafe_allow_html=True)


def show_severity_badge(severity: str) -> None:
    safe = severity if severity in {"Informational", "Low", "Medium", "High", "Critical"} else "Medium"
    st.markdown(f"<span class='severity-badge severity-{safe}'>{safe}</span>", unsafe_allow_html=True)


def build_incident_timeline(rule_analysis: dict, llm_analysis: dict) -> list[dict]:
    categories = ", ".join(rule_analysis.get("detected_categories", [])) or "no deterministic match"
    severity = llm_analysis.get("severity", "Unknown")
    return [
        {
            "stage": "Alert Received",
            "description": "Bank SOC receives alert from the selected banking security source.",
        },
        {
            "stage": "Rule Pre-Analysis",
            "description": f"Rule engine detected: {categories}. Severity hint: {rule_analysis.get('severity_hint', 'N/A')}.",
        },
        {
            "stage": "Local LLM Analysis",
            "description": f"Ollama classified the event as {llm_analysis.get('attack_type', 'Unknown')} with {severity} severity.",
        },
        {
            "stage": "Containment Guidance",
            "description": "SOC analyst reviews recommended steps, affected assets, IOCs, and MITRE mapping.",
        },
        {
            "stage": "Report Integrity",
            "description": "Incident report is saved with SHA-256 hash and HMAC signature for later verification.",
        },
    ]


def save_analysis_package(package: dict, analyst_decision: str) -> dict[str, str]:
    report = build_report_record(
        package["alert_text"],
        package["model"],
        package["rule_analysis"],
        package["llm_analysis"],
        package["mitre_mapping"],
        package["ioc_enrichment"],
        package["confidence_comparison"],
        package["incident_timeline"],
        analyst_decision,
    )
    return save_report(report)


@st.cache_data(show_spinner=False)
def load_sample_alerts() -> list[dict]:
    if not SAMPLES_PATH.exists():
        raise FileNotFoundError("sample_alerts.json is missing.")
    return json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))


def selected_model() -> str:
    st.sidebar.header("Local LLM")
    choice = st.sidebar.selectbox("Model", ["llama3.2", "mistral", "qwen2.5", "Custom"])
    if choice == "Custom":
        custom = st.sidebar.text_input("Custom model name", placeholder="example: llama3.1:8b")
        return custom.strip() or "llama3.2"
    return choice


def dashboard() -> None:
    history = load_report_history()
    total = len(history)
    severities = [item.get("llm_analysis", {}).get("severity", "Unknown") for item in history]
    attack_types = [item.get("llm_analysis", {}).get("attack_type", "Unknown") for item in history]
    last_hash = "No report yet"

    metadata_files = list_integrity_metadata()
    if metadata_files:
        try:
            metadata = json.loads(metadata_files[0].read_text(encoding="utf-8"))
            last_hash = metadata.get("json_sha256", "Unavailable")
        except (json.JSONDecodeError, OSError):
            last_hash = "Unavailable"

    col1, col2, col3 = st.columns(3)
    col1.metric("Analyzed alerts", total)
    col2.metric("Stored reports", len(metadata_files))
    col3.metric("Last report hash", last_hash[:16] + "..." if len(last_hash) > 20 else last_hash)

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("Alerts by Severity")
        if severities:
            st.bar_chart(pd.Series(severities).value_counts())
        else:
            st.info("No analyzed alerts yet.")
    with chart_col2:
        st.subheader("Alerts by Attack Type")
        if attack_types:
            st.bar_chart(pd.Series(attack_types).value_counts())
        else:
            st.info("No attack classifications yet.")


def render_analysis_results(package: dict) -> None:
    llm_analysis = package["llm_analysis"]
    saved = package["saved"]

    st.subheader("LLM SOC Analysis")
    show_severity_badge(llm_analysis.get("severity", "Medium"))
    show_light_json(llm_analysis)

    st.subheader("Confidence Comparison")
    confidence = package["confidence_comparison"]
    col1, col2, col3 = st.columns(3)
    col1.metric("Rule confidence", f"{confidence['rule_confidence_score']}/100")
    col2.metric("LLM confidence", f"{llm_analysis['confidence_score']}/100")
    col3.metric("IOC risk", package["ioc_enrichment"]["overall_ioc_risk_level"])
    st.caption(confidence["basis"])

    st.subheader("IOC Enrichment")
    enrichment_items = package["ioc_enrichment"].get("items", [])
    if enrichment_items:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "indicator": item["indicator"],
                        "type": item["type"],
                        "risk_score": item["risk_score"],
                        "risk_level": item["risk_level"],
                        "notes": " | ".join(item.get("notes", [])),
                        "lookup_links": " | ".join(item.get("lookup_links", [])),
                    }
                    for item in enrichment_items
                ]
            ),
            use_container_width=True,
        )
        st.caption(package["ioc_enrichment"]["privacy_note"])
    else:
        st.info("No extracted IOCs were available for enrichment.")

    st.subheader("Incident Timeline")
    for event in package["incident_timeline"]:
        st.markdown(
            f"<div class='workflow-card'><strong>{html.escape(event['stage'])}</strong><br>"
            f"{html.escape(event['description'])}</div>",
            unsafe_allow_html=True,
        )

    st.subheader("MITRE ATT&CK Mapping")
    st.dataframe(pd.DataFrame(package["mitre_mapping"]), use_container_width=True)

    st.subheader("Analyst Decision")
    action_cols = st.columns(4)
    actions = ["Confirm Incident", "Mark False Positive", "Escalate to Tier 2", "Close Alert"]
    for column, action in zip(action_cols, actions):
        if column.button(action, key=f"analyst_{action}"):
            package["analyst_decision"] = action
            package["saved"] = save_analysis_package(package, action)
            st.session_state["latest_analysis"] = package
            st.success(f"Analyst decision saved: {action}")
    st.info(f"Current analyst decision: {package.get('analyst_decision', 'Pending Analyst Review')}")

    st.subheader("Generated Reports")
    col1, col2 = st.columns(2)
    col1.code(package["saved"]["json_path"], language="text")
    col2.code(package["saved"]["txt_path"], language="text")

    json_path = Path(package["saved"]["json_path"])
    txt_path = Path(package["saved"]["txt_path"])
    if json_path.exists():
        st.download_button(
            "Download JSON Report",
            json_path.read_bytes(),
            file_name=json_path.name,
            mime="application/json",
        )
    if txt_path.exists():
        st.download_button(
            "Download TXT Report",
            txt_path.read_text(encoding="utf-8"),
            file_name=txt_path.name,
            mime="text/plain",
        )

    st.caption(f"JSON SHA-256: {package['saved']['json_hash']}")
    st.caption(f"JSON HMAC: {package['saved']['json_hmac_signature']}")


def report_verification() -> None:
    st.subheader("Report Integrity Verification")
    metadata_files = list_integrity_metadata()
    if not metadata_files:
        st.info("No saved report metadata found yet.")
        return

    selected_meta = st.selectbox("Select saved report metadata", metadata_files, format_func=lambda p: p.name)
    metadata = json.loads(selected_meta.read_text(encoding="utf-8"))
    report_type = st.radio("Report file to verify", ["JSON", "TXT"], horizontal=True)

    if report_type == "JSON":
        report_path = REPORTS_DIR / metadata["json_report"]
        expected_hash = metadata["json_sha256"]
        expected_signature = metadata["json_hmac_signature"]
    else:
        report_path = REPORTS_DIR / metadata["txt_report"]
        expected_hash = metadata["txt_sha256"]
        expected_signature = metadata["txt_hmac_signature"]

    if st.button("Verify Selected Report"):
        if not report_path.exists():
            st.error(f"Report file is missing: {report_path.name}")
            return
        result = verify_report_integrity(report_path, expected_hash, expected_signature)
        if result["is_valid"]:
            st.success("Report integrity verified. Hash and HMAC signature match.")
        else:
            st.error("Verification failed. The report may have been modified.")
        show_light_json(result)


def presentation_mode() -> None:
    st.subheader("Presentation Mode")
    st.markdown(
        """
        This project demonstrates how a bank SOC can use a local LLM to speed up alert triage
        while keeping sensitive security data inside the local environment.
        """
    )

    st.markdown("### Architecture")
    architecture = [
        {
            "stage": "1. Bank Alert Input",
            "description": "Analyst selects a sample bank alert or enters a custom alert from SIEM, WAF, ATM, EDR, firewall, or email security systems.",
        },
        {
            "stage": "2. Rule Engine",
            "description": "Deterministic checks detect SQL injection, XSS, phishing, brute force, malware, data exfiltration, ATM fraud, and extract IOCs.",
        },
        {
            "stage": "3. Local Ollama LLM",
            "description": "The alert and rule context are sent to a local model through http://localhost:11434/api/chat. No OpenAI API is used.",
        },
        {
            "stage": "4. SOC Analysis",
            "description": "The model returns structured JSON with severity, confidence, business impact, remediation, and a final incident report.",
        },
        {
            "stage": "5. Reporting and Integrity",
            "description": "Reports are saved as JSON and TXT, then protected with SHA-256 hashes and HMAC signatures.",
        },
    ]
    for item in architecture:
        st.markdown(
            f"<div class='workflow-card'><strong>{html.escape(item['stage'])}</strong><br>"
            f"{html.escape(item['description'])}</div>",
            unsafe_allow_html=True,
        )

    st.markdown("### Why Local LLMs Fit A Bank SOC")
    st.write(
        "- Bank alerts may contain customer identifiers, employee emails, server names, IP addresses, and transaction patterns.\n"
        "- A local LLM reduces the risk of sending sensitive alert content to cloud providers.\n"
        "- IOC enrichment is kept local and limited to extracted indicators, with manual lookup links for analysts.\n"
        "- Human analysts still validate the final incident decision."
    )

    st.markdown("### Demo Script")
    st.write(
        "1. Choose `llama3.2` in the sidebar.\n"
        "2. Select the SQL injection, phishing, or malware sample alert.\n"
        "3. Run SOC analysis.\n"
        "4. Explain the rule-based findings and extracted IOCs.\n"
        "5. Show the local LLM output, severity badge, timeline, and MITRE mapping.\n"
        "6. Use an analyst action button.\n"
        "7. Download the report and verify its integrity."
    )


def analysis_workspace(model: str) -> None:
    st.subheader("Analyze Bank Security Alert")
    try:
        samples = load_sample_alerts()
    except FileNotFoundError as exc:
        st.error(str(exc))
        samples = []
    except json.JSONDecodeError:
        st.error("sample_alerts.json is invalid JSON.")
        samples = []

    method = st.radio("Alert input method", ["Choose sample bank alert", "Enter custom alert"], horizontal=True)
    alert_text = ""

    if method == "Choose sample bank alert" and samples:
        selected = st.selectbox("Sample alerts", samples, format_func=lambda item: item["title"])
        st.caption(f"Source: {selected['source']} | Scenario: {selected['scenario']}")
        alert_text = st.text_area("Alert content", selected["alert"], height=220)
    else:
        alert_text = st.text_area(
            "Custom alert",
            placeholder="Paste a bank SOC alert from online banking, ATM, firewall, login, or email security systems.",
            height=260,
        )

    if st.button("Run SOC Analysis", type="primary"):
        if not alert_text.strip():
            st.warning("Enter or select an alert before analysis.")
            return

        with st.spinner("Running rule-based pre-analysis..."):
            rule_analysis = analyze_alert(alert_text)
            ioc_enrichment = enrich_indicators(rule_analysis.get("indicators", {}))
            confidence_comparison = calculate_rule_confidence(rule_analysis)

        st.subheader("Rule-Based Pre-Analysis")
        show_light_json(rule_analysis)
        st.subheader("Rule vs LLM Confidence Preview")
        col1, col2 = st.columns(2)
        col1.metric("Rule confidence", f"{confidence_comparison['rule_confidence_score']}/100")
        col2.metric("IOC risk", ioc_enrichment["overall_ioc_risk_level"])

        try:
            with st.spinner(f"Calling local Ollama model: {model}"):
                llm_analysis = analyze_with_ollama(model, alert_text, rule_analysis)
        except OllamaError as exc:
            st.error(str(exc))
            return
        except Exception as exc:
            st.error(f"Unexpected analysis error: {exc}")
            return

        mitre_mapping = map_to_mitre(
            rule_analysis.get("detected_categories", []),
            llm_analysis.get("attack_type", ""),
        )
        incident_timeline = build_incident_timeline(rule_analysis, llm_analysis)
        report = build_report_record(
            alert_text,
            model,
            rule_analysis,
            llm_analysis,
            mitre_mapping,
            ioc_enrichment,
            confidence_comparison,
            incident_timeline,
        )
        saved = save_report(report)
        package = {
            "alert_text": alert_text,
            "model": model,
            "rule_analysis": rule_analysis,
            "llm_analysis": llm_analysis,
            "mitre_mapping": mitre_mapping,
            "ioc_enrichment": ioc_enrichment,
            "confidence_comparison": confidence_comparison,
            "incident_timeline": incident_timeline,
            "analyst_decision": "Pending Analyst Review",
            "saved": saved,
        }
        st.session_state["latest_analysis"] = package

        st.success("Incident report generated and saved with SHA-256 and HMAC integrity metadata.")
        render_analysis_results(package)
    elif "latest_analysis" in st.session_state:
        render_analysis_results(st.session_state["latest_analysis"])


def main() -> None:
    apply_styles()
    st.markdown(
        """
        <div class="soc-banner">
          <h1>Bank SOC Assistant</h1>
          <p>Local LLM-based security alert analyzer for banking environments using Ollama.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    model = selected_model()
    st.sidebar.caption("API endpoint: http://localhost:11434/api/chat")
    st.sidebar.caption("No OpenAI API or cloud LLM is used.")

    tabs = st.tabs(["SOC Analysis", "Dashboard", "Verify Reports", "Presentation"])
    with tabs[0]:
        analysis_workspace(model)
    with tabs[1]:
        dashboard()
    with tabs[2]:
        report_verification()
    with tabs[3]:
        presentation_mode()


if __name__ == "__main__":
    main()
