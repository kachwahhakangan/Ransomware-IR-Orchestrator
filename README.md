# Ransomware IR Orchestrator

A Python-based security orchestration project designed to support ransomware incident response by receiving security alerts, creating incident records, tracking evidence metadata, and recording simulated response actions.

## Project Overview

Security teams need to investigate alerts quickly, preserve evidence, and coordinate incident response.

The Ransomware IR Orchestrator demonstrates how these activities can be organized through a REST API backed by a persistent SQLite database.

This project is developed as a cybersecurity learning and portfolio project.

## Features

- **EDR Alert Ingestion:** Receive security alerts through a webhook.
- **Incident Management:** Create and retrieve incident records.
- **Severity-Based Response:** Select response workflows based on alert severity.
- **Incident Statistics:** Retrieve summary statistics about recorded incidents.
- **Evidence Management:** Associate evidence metadata with incidents.
- **Evidence Integrity Verification:** Calculate and verify SHA-256 hashes of evidence files.
- **Response Action Tracking:** Record simulated incident response actions.
- **Persistent Storage:** Store incidents, evidence metadata, and response actions in SQLite.
- **Interactive API Documentation:** Explore and test endpoints through Swagger UI.
- **Automated Tests:** Run regression tests for evidence integrity functionality.

## Technology Stack

- Python
- FastAPI
- SQLite
- Pydantic
- Uvicorn
- Ruff
- unittest
- Git and GitHub
- SHA-256 hashing

## Project Structure

```text
Ransomware-IR-Orchestrator/
├── app/
│   ├── main.py
│   ├── database.py
│   └── evidence_integrity.py
├── tests/
│   └── test_evidence_integrity.py
├── evidence/
├── alerts/
├── logs/
├── .gitignore
├── README.md
└── requirements.txt
```

The SQLite database is created locally under `data/incidents.db` when the application initializes. Local database files and virtual environments should not be committed to the repository.

## Prerequisites

- Python installed on your computer
- Git
- A terminal such as PowerShell
- A code editor such as Visual Studio Code

## Setup and Installation

Clone the repository:

```powershell
git clone https://github.com/kachwahhakangan/Ransomware-IR-Orchestrator.git
```

Enter the project directory:

```powershell
cd Ransomware-IR-Orchestrator
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Install the project dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Install Ruff if it is not already available:

```powershell
.\.venv\Scripts\python.exe -m pip install ruff
```

## Running the Application

Start the development server:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open the interactive API documentation:

http://127.0.0.1:8000/docs

The local API base address is:

http://127.0.0.1:8000

The development server is intended for local testing, not production deployment.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Check application status |
| POST | `/webhook/edr` | Receive an EDR alert |
| GET | `/incidents` | Retrieve all incidents |
| GET | `/incidents/stats` | Retrieve incident statistics |
| GET | `/incidents/{incident_id}` | Retrieve an individual incident |
| POST | `/incidents/{incident_id}/evidence` | Record evidence metadata |
| GET | `/incidents/{incident_id}/evidence` | Retrieve evidence associated with an incident |
| POST | `/evidence/verify-integrity` | Verify an evidence file's SHA-256 hash |
| GET | `/evidence/{evidence_id}` | Retrieve an evidence record |
| GET | `/incidents/{incident_id}/response-actions` | Retrieve recorded response actions |

## Evidence Integrity Verification

The project uses SHA-256 hashing to help detect changes to evidence files.

The integrity verification workflow:

1. Select an evidence file stored in the project's `evidence/` directory.
2. Calculate its SHA-256 hash.
3. Compare the calculated hash with the expected hash.
4. Return whether the hashes match.

The verification endpoint accepts an evidence filename and an expected SHA-256 hash.

Only filenames are accepted; arbitrary filesystem paths are rejected. Missing evidence files return an error.

A matching hash indicates that the file matches the supplied expected digest. It does not, by itself, prove who created the file or establish a complete chain of custody.

## Database

The project uses SQLite for persistent storage.

The database maintains records for:

- Incidents
- Evidence metadata
- Response actions

The database is initialized when the FastAPI application starts.

## Testing

Run the automated regression tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Run the code-quality checks:

```powershell
.\.venv\Scripts\python.exe -m ruff check app tests --output-format concise
```

Compile the application modules:

```powershell
.\.venv\Scripts\python.exe -m compileall -q app
```

The evidence integrity tests cover hash calculation, successful verification, modified evidence, missing files, and invalid hash formats.

## Security and Limitations

This is a learning and demonstration project.

- Host isolation and account suspension are simulated response actions; they do not perform real containment.
- Evidence metadata recording does not automatically collect a memory dump or other forensic artifacts.
- Evidence integrity verification requires the evidence file to be available locally in the designated directory.
- The development webhook secret must be replaced with secure configuration before any real deployment.
- The application has not been presented as production-hardened or independently security-audited.

Do not connect this demonstration to production systems or use it to perform real containment without implementing and testing appropriate authentication, authorization, secrets management, auditing, and safeguards.

## Future Improvements

- Add comprehensive automated API tests.
- Implement environment-based secret management.
- Add authentication and role-based authorization.
- Improve structured audit logging and chain-of-custody records.
- Integrate with a test EDR environment.
- Add carefully controlled integrations for real response actions.
- Develop deployment and monitoring documentation.

## Learning Objectives

This project demonstrates practical concepts in:

- Security orchestration and incident response
- REST API development
- Python application structure
- Relational database persistence
- Digital evidence integrity
- Automated software testing
- Secure development practices

## Repository

GitHub: https://github.com/kachwahhakangan/Ransomware-IR-Orchestrator

---

**Disclaimer:** This project is intended for educational purposes and authorized security testing.