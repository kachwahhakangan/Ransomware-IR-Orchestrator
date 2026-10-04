# Automated Ransomware Containment & Incident Response Orchestrator

A Python-based security orchestration platform designed to automate
ransomware incident response workflows.

## Project Objective

The project aims to automate critical incident response actions
when a severe security alert is detected.

Planned response actions include:

- EDR alert ingestion
- Alert parsing and enrichment
- Automated host containment
- Identity response
- Forensic evidence collection
- Secure evidence storage
- Chain-of-custody logging
- Incident ticket creation
- SOC team notifications

## Technology Stack

- Python
- FastAPI
- EDR APIs
- AWS
- Amazon S3
- Volatility
- KAPE
- Git/GitHub

## Current Status

### Week 1 - Day 1

- Project repository created
- Python virtual environment configured
- FastAPI application created
- Uvicorn development server configured
- Initial API endpoint implemented
- API tested successfully using Swagger UI

## Project Structure

```text
Ransomware-IR-Orchestrator/
│
├── app/
│   └── main.py
│
├── tests/
├── alerts/
├── evidence/
├── logs/
│
├── requirements.txt
├── README.md
└── .gitignore

## Week 1 Progress

### Day 7 — EDR Ingestion Pipeline Validation

The Week 1 EDR ingestion pipeline was tested end-to-end.

Validated:

- Webhook authentication
- EDR alert payload validation
- Alert indicator extraction
- Hostname extraction
- IP extraction
- User extraction
- Process extraction
- SHA-256 extraction
- Severity classification
- Incident creation

The complete pipeline was successfully tested using a sandbox EDR alert through the FastAPI webhook.

**Status: Week 1 complete.**