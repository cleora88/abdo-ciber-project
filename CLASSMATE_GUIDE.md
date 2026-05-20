# Classmate Setup Guide

This guide explains what to install and how to run the **Bank SOC Assistant: Local LLM-Based Security Alert Analyzer** project.

## 1. Install Python

Install Python 3.10 or newer.

Check that Python works:

```bash
python --version
```

## 2. Install Ollama

Install Ollama from:

```text
https://ollama.com
```

After installation, open a terminal and check:

```bash
ollama --version
```

## 3. Download A Local LLM Model

The project supports these free local models:

```bash
ollama pull llama3.2
ollama pull mistral
ollama pull qwen2.5
```

For a faster demo, use `llama3.2` first:

```bash
ollama pull llama3.2
```

## 4. Start Ollama

Ollama usually starts automatically. If the app says Ollama is not running, use:

```bash
ollama serve
```

The project calls Ollama at:

```text
http://localhost:11434/api/chat
```

## 5. Open The Project Folder

Go into the project folder:

```bash
cd bank_soc_llm_assistant
```

## 6. Create A Virtual Environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 7. Install Python Dependencies

```bash
pip install -r requirements.txt
```

## 8. Run The Streamlit App

```bash
streamlit run app.py
```

Open the local URL shown in the terminal. Usually it is:

```text
http://localhost:8501
```

## 9. How To Demo The Project

1. Select `llama3.2` in the sidebar.
2. Choose a sample alert, such as SQL injection or phishing.
3. Click **Run SOC Analysis**.
4. Show the rule-based pre-analysis.
5. Show the LLM SOC analysis.
6. Show the MITRE ATT&CK mapping.
7. Open the dashboard tab.
8. Open the verification tab and verify a saved report.

## 10. Common Problems

### Ollama Is Not Running

Run:

```bash
ollama serve
```

### Model Is Not Installed

If the selected model is missing, run one of:

```bash
ollama pull llama3.2
ollama pull mistral
ollama pull qwen2.5
```

### Streamlit Command Not Found

Make sure dependencies are installed:

```bash
pip install -r requirements.txt
```

### LLM JSON Error

Local models sometimes return text that is not valid JSON. Run the analysis again or use `llama3.2`.

## 11. Important Notes

- This project does not use OpenAI API.
- Alerts are analyzed locally through Ollama.
- It is an educational prototype, not a production SOC tool.
- Final incident decisions should always be reviewed by a human analyst.
