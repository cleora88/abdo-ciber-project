# Bank SOC Assistant: Local LLM-Based Security Alert Analyzer

This project is a university cybersecurity prototype for the topic:

**Using Large Language Models to Assist a Security Operations Center (SOC) in Analyzing Security Alerts**

The scenario is a bank SOC that receives alerts from online banking systems, ATM systems, firewall logs, login systems, endpoint security, and email security gateways. The application performs rule-based pre-analysis, sends the alert to a local Ollama model, maps likely activity to MITRE ATT&CK, and saves incident reports with cryptographic integrity metadata.

## Why Local LLMs Matter for a Bank SOC

Banks handle sensitive information such as customer accounts, authentication events, transaction patterns, card data, employee identities, and infrastructure details. A local LLM keeps alert content on the analyst machine or internal network instead of sending it to an external AI API.

Benefits:

- Better privacy for bank customers and employees
- Reduced exposure of sensitive infrastructure details
- Useful SOC assistance without cloud dependency
- Lower cost for demos, labs, and university projects
- Easier discussion of data governance and regulatory concerns

This project uses Ollama through the local endpoint:

```bash
http://localhost:11434/api/chat
```

No OpenAI API is used.

## Features

- Streamlit bank-themed SOC interface
- Local model selector for `llama3.2`, `mistral`, `qwen2.5`, or a custom Ollama model name
- Sample and manual alert input
- Rule-based pre-analysis before LLM analysis
- IOC extraction for IPs, URLs, emails, and hashes
- Structured JSON LLM output
- Simple MITRE ATT&CK mapping
- Incident report generation in JSON and TXT
- SHA-256 hash generation for each report
- HMAC signature generation using a secret key
- Report integrity verification feature
- Dashboard with analyzed alert count, severity chart, attack type chart, and latest report hash
- Privacy-conscious IOC enrichment with risk scores and manual lookup links
- Rule confidence vs LLM confidence comparison
- Severity color badges
- Incident response timeline
- Analyst decision buttons for confirm, false positive, escalation, and closure
- JSON and TXT report download buttons
- Presentation tab for classroom demos
- Error handling for Ollama availability, missing models, invalid JSON, and missing files

## Project Structure

```text
bank_soc_llm_assistant/
|
|-- app.py
|-- ollama_client.py
|-- rule_engine.py
|-- threat_intel.py
|-- mitre_mapper.py
|-- report_generator.py
|-- crypto_utils.py
|-- sample_alerts.json
|-- requirements.txt
|-- README.md
`-- reports/
```

## Installation

1. Create and activate a Python virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Install Ollama from the official Ollama website, then pull local models:

```bash
ollama pull llama3.2
ollama pull mistral
ollama pull qwen2.5
```

4. Start Ollama if it is not already running:

```bash
ollama serve
```

5. Run the Streamlit application:

```bash
streamlit run app.py
```

## Demo Scenarios

The included `sample_alerts.json` contains realistic bank SOC scenarios:

- Online banking brute-force login
- Phishing email targeting bank employees
- SQL injection attempt on banking portal
- Suspicious ATM withdrawals
- Abnormal outbound traffic and possible data exfiltration
- Malware alert on an employee workstation
- Impossible travel login
- Suspicious SWIFT transfer approval
- Ransomware behavior on a file server
- Privileged account misuse

For a presentation, choose one scenario, run the rule-based pre-analysis, then show how the local LLM produces a structured SOC report. After report creation, use the verification tab to prove that the saved report has not been modified.

The app also includes a **Presentation** tab with a simple architecture explanation and demo script.

## Expected LLM Output

The LLM is instructed to return JSON with:

- `alert_summary`
- `attack_type`
- `severity`
- `confidence_score`
- `indicators_of_compromise`
- `affected_assets`
- `business_impact_for_bank`
- `technical_explanation`
- `recommended_remediation_steps`
- `false_positive_possibility`
- `final_incident_report`

## Report Integrity

Each generated report is saved in `reports/` as:

- JSON report
- TXT report
- Integrity metadata file

The metadata stores SHA-256 hashes and HMAC signatures. By default, the demo uses a built-in secret key. For a stronger setup, define your own key before running the app:

```bash
set BANK_SOC_HMAC_SECRET=your-long-secret-key
```

PowerShell:

```powershell
$env:BANK_SOC_HMAC_SECRET="your-long-secret-key"
```

## Limitations

- This is an educational prototype, not a production SIEM or SOAR platform.
- LLM output can be wrong, incomplete, or inconsistent.
- MITRE mapping is intentionally simple and rule-based.
- The app does not ingest live bank logs.
- HMAC key management is simplified for demonstration.
- The project depends on Ollama and the selected model being installed locally.
- Analysts must validate final incident conclusions before real-world action.

## Presentation Notes

Good points to explain:

- Rule-based detection catches obvious technical indicators quickly.
- The LLM adds analyst-style context, business impact, and remediation guidance.
- Local models support privacy-sensitive banking environments.
- Hashing and HMAC signatures help demonstrate report integrity.
- The dashboard gives SOC managers a simple overview of analyzed alerts.

## Extra Documents

- `CLASSMATE_GUIDE.md`: short installation and running guide for classmates.
- `PROJECT_REPORT.md`: written project report source.
- `PROJECT_REPORT.pdf`: PDF version of the project report for submission or presentation.
