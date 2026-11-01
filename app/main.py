from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.database import get_connection, initialize_database
from app.evidence_integrity import calculate_sha256

# ==========================================
# 1. INITIALIZE THE APPLICATION
# ==========================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Ransomware IR Orchestrator",
    description="Automated ransomware containment and incident response platform",
    version="0.1.0",
    lifespan=lifespan,
)


# ==========================================
# 2. CONFIGURATION
# ==========================================

# Development-only webhook secret.
# Use an environment variable for real deployments.
WEBHOOK_SECRET = "dev-edr-secret-123"


# ==========================================
# 3. DATA MODELS
# ==========================================

class EDRAlert(BaseModel):
    alert_id: str = Field(..., min_length=1)
    severity: str = Field(
        ...,
        pattern="^(critical|high|medium|low)$",
    )
    hostname: str
    ip: str
    user: str
    process: str
    sha256: str


class AlertIndicators(BaseModel):
    hostname: str
    ip: str
    user: str
    process: str
    sha256: str


class ForensicEvidence(BaseModel):
    evidence_id: str
    incident_id: str
    hostname: str
    evidence_type: str
    collection_status: str
    sha256: str | None = None


class EvidenceRequest(BaseModel):
    evidence_type: str = Field(..., min_length=1)
    sha256: str | None = None

class EvidenceIntegrityRequest(BaseModel):
    file_name: str = Field(..., min_length=1)
    expected_sha256: str = Field(..., min_length=64, max_length=64)


class Incident(BaseModel):
    incident_id: str
    alert_id: str
    severity: str
    hostname: str
    ip: str
    user: str
    process: str
    sha256: str
    status: str


class ContainmentAction(BaseModel):
    action: str
    hostname: str
    status: str
    management_connection: str


class AccountAction(BaseModel):
    action: str
    username: str
    status: str
    result: str


class ResponseActionLog(BaseModel):
    incident_id: str
    action: str
    target: str
    status: str
    result: str

class ResponseActionUpdate(BaseModel):
    status: str = Field(
        ...,
        pattern="^(PENDING|IN_PROGRESS|COMPLETED|FAILED)$",
    )
    result: str = Field(..., min_length=1, max_length=500)

class ContainmentResult(BaseModel):
    hostname: str
    action: str
    result: str
    management_connection: str


class ResponsePlaybook(BaseModel):
    name: str
    severity: str
    action: str
    status: str


# ==========================================
# 4. HELPER FUNCTIONS
# ==========================================

def extract_indicators(alert: EDRAlert) -> AlertIndicators:
    return AlertIndicators(
        hostname=alert.hostname,
        ip=alert.ip,
        user=alert.user,
        process=alert.process,
        sha256=alert.sha256,
    )


def contain_host(hostname: str) -> ContainmentAction:
    return ContainmentAction(
        action="NETWORK_ISOLATION",
        hostname=hostname,
        status="REQUESTED",
        management_connection="MAINTAINED",
    )


def execute_containment(
    action: ContainmentAction,
) -> ContainmentResult:
    return ContainmentResult(
        hostname=action.hostname,
        action=action.action,
        result="SIMULATED_SUCCESS",
        management_connection=action.management_connection,
    )


def suspend_account(username: str) -> AccountAction:
    return AccountAction(
        action="ACCOUNT_SUSPENSION",
        username=username,
        status="REQUESTED",
        result="SIMULATED_SUCCESS",
    )


def select_playbook(severity: str) -> ResponsePlaybook:
    normalized = severity.strip().lower()

    if normalized in ["critical", "high"]:
        return ResponsePlaybook(
            name="RANSOMWARE_CONTAINMENT",
            severity=normalized.upper(),
            action="NETWORK_ISOLATION",
            status="READY",
        )

    return ResponsePlaybook(
        name="MONITORING",
        severity=normalized.upper(),
        action="NONE",
        status="NO_ACTION_REQUIRED",
    )


def log_incident_event(
    incident_id: str,
    event_type: str,
    description: str,
):
    """Record an incident event in the database."""
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO incident_events (
                event_id,
                incident_id,
                event_type,
                description
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                f"EVT-{uuid4().hex[:8]}",
                incident_id,
                event_type,
                description,
            ),
        )


# ==========================================
# 5. ROOT ENDPOINT
# ==========================================

@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational",
    }


# ==========================================
# 6. INCIDENT ENDPOINTS
# ==========================================

@app.get("/incidents")
def get_all_incidents(
    severity: str | None = None,
    status: str | None = None,
    hostname: str | None = None,
    limit: int = 10,
    offset: int = 0,
):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=422,
            detail="Limit must be between 1 and 100",
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="Offset cannot be negative",
        )

    query = "SELECT * FROM incidents"
    conditions = []
    parameters = []

    if severity:
        conditions.append("LOWER(severity) = LOWER(?)")
        parameters.append(severity)

    if status:
        conditions.append("UPPER(status) = UPPER(?)")
        parameters.append(status)

    if hostname:
        conditions.append("LOWER(hostname) LIKE LOWER(?)")
        parameters.append(f"%{hostname}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])

    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()

    return [dict(row) for row in rows]

@app.get("/incidents/stats")
def get_incident_stats():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT severity, status FROM incidents"
        ).fetchall()

    incidents = [dict(row) for row in rows]

    return {
        "total_incidents": len(incidents),
        "critical_incidents": sum(
            1
            for incident in incidents
            if incident["severity"].lower() == "critical"
        ),
        "high_incidents": sum(
            1
            for incident in incidents
            if incident["severity"].lower() == "high"
        ),
        "response_required": sum(
            1
            for incident in incidents
            if incident["status"] == "RESPONSE_REQUIRED"
        ),
        "monitoring": sum(
            1
            for incident in incidents
            if incident["status"] == "MONITOR"
        ),
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return dict(row)

@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str):
    with get_connection() as connection:
        incident = connection.execute(
            "SELECT incident_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        rows = connection.execute(
            """
            SELECT
                event_id,
                incident_id,
                event_type,
                description,
                created_at
            FROM incident_events
            WHERE incident_id = ?
            ORDER BY created_at ASC, rowid ASC
            """,
            (incident_id,),
        ).fetchall()

    events = [dict(row) for row in rows]

    return {
        "incident_id": incident_id,
        "total_events": len(events),
        "timeline": events,
    }


@app.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: str):
    with get_connection() as connection:
        incident_row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident_row is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        evidence_rows = connection.execute(
            """
            SELECT
                evidence_id,
                incident_id,
                hostname,
                evidence_type,
                collection_status,
                sha256
            FROM evidence
            WHERE incident_id = ?
            ORDER BY rowid
            """,
            (incident_id,),
        ).fetchall()

        action_rows = connection.execute(
            """
            SELECT
                action_id,
                incident_id,
                action,
                target,
                status,
                result,
                created_at
            FROM response_actions
            WHERE incident_id = ?
            ORDER BY created_at, action_id
            """,
            (incident_id,),
        ).fetchall()

    incident = dict(incident_row)
    evidence = [dict(row) for row in evidence_rows]
    actions = [dict(row) for row in action_rows]

    return {
        "incident_id": incident_id,
        "incident": incident,
        "evidence_summary": {
            "total": len(evidence),
        },
        "response_summary": {
            "total": len(actions),
            "completed": sum(
                1 for action in actions
                if action["status"].upper() == "COMPLETED"
            ),
            "failed": sum(
                1 for action in actions
                if action["status"].upper() == "FAILED"
            ),
            "in_progress": sum(
                1 for action in actions
                if action["status"].upper() == "IN_PROGRESS"
            ),
            "pending": sum(
                1 for action in actions
                if action["status"].upper() == "PENDING"
            ),
        },
        "evidence": evidence,
        "response_actions": actions,
    }

# ==========================================
# 7. FORENSIC EVIDENCE ENDPOINTS
# ==========================================

@app.post("/incidents/{incident_id}/evidence")
def record_evidence(
    incident_id: str,
    request: EvidenceRequest,
):
    with get_connection() as connection:
        incident = connection.execute(
            "SELECT hostname FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        evidence = ForensicEvidence(
            evidence_id=f"EVD-{uuid4().hex[:8]}",
            incident_id=incident_id,
            hostname=incident["hostname"],
            evidence_type=request.evidence_type.strip().upper(),
            collection_status="SIMULATED_NOT_COLLECTED",
            sha256=request.sha256,
        )

        connection.execute(
            """
            INSERT INTO evidence (
                evidence_id,
                incident_id,
                hostname,
                evidence_type,
                collection_status,
                sha256
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.evidence_id,
                evidence.incident_id,
                evidence.hostname,
                evidence.evidence_type,
                evidence.collection_status,
                evidence.sha256,
            ),
        )

    # Record the evidence event in the incident timeline.
    log_incident_event(
        incident_id=incident_id,
        event_type="EVIDENCE_RECORDED",
        description=(
            f"Evidence metadata recorded: "
            f"{evidence.evidence_type} "
            f"(ID: {evidence.evidence_id})."
        ),
    )
    return {
        "message": "Evidence metadata recorded",
        "note": "No actual forensic evidence was collected",
        "evidence": evidence,
    }


@app.get("/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: str):
    with get_connection() as connection:
        incident = connection.execute(
            "SELECT incident_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        rows = connection.execute(
            "SELECT * FROM evidence WHERE incident_id = ?",
            (incident_id,),
        ).fetchall()

    evidence_records = [dict(row) for row in rows]

    return {
        "incident_id": incident_id,
        "total_evidence_records": len(evidence_records),
        "evidence_records": evidence_records,
    }
@app.post("/evidence/verify-integrity")
def verify_evidence_integrity(request: EvidenceIntegrityRequest):
    # Restrict access to files inside the project's evidence directory.
    evidence_dir = (Path(__file__).resolve().parent.parent / "evidence").resolve()

    # Accept filenames only, not arbitrary filesystem paths.
    if Path(request.file_name).name != request.file_name:
        raise HTTPException(
            status_code=400,
            detail="Only evidence filenames are allowed.",
        )

    file_path = (evidence_dir / request.file_name).resolve()

    # Verify that the resolved path stays inside the evidence directory.
    if not file_path.is_relative_to(evidence_dir):
        raise HTTPException(
            status_code=400,
            detail="Invalid evidence file path.",
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Evidence file not found.",
        )

    try:
        actual_sha256 = calculate_sha256(file_path)
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Unable to read the evidence file.",
        )

    integrity_verified = (
        actual_sha256.lower() == request.expected_sha256.lower()
    )

    return {
        "file_name": request.file_name,
        "expected_sha256": request.expected_sha256,
        "actual_sha256": actual_sha256,
        "integrity_verified": integrity_verified,
        "status": "INTEGRITY_VERIFIED"
        if integrity_verified
        else "INTEGRITY_MISMATCH",
    }

@app.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence record not found",
        )

    return dict(row)


# ==========================================
# 8. EDR WEBHOOK ENDPOINT
# ==========================================

@app.get("/incidents/{incident_id}/response-actions")
def get_incident_response_actions(incident_id: str):
    with get_connection() as connection:
        incident = connection.execute(
            "SELECT incident_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        rows = connection.execute(
            """
            SELECT
                action_id,
                incident_id,
                action,
                target,
                status,
                result,
                created_at
            FROM response_actions
            WHERE incident_id = ?
            ORDER BY created_at, action_id
            """,
            (incident_id,),
        ).fetchall()

        response_actions = [dict(row) for row in rows]

    return {
        "incident_id": incident_id,
        "total_actions": len(response_actions),
        "response_actions": response_actions,
    }

@app.patch(
    "/incidents/{incident_id}/response-actions/{action_id}"
)
def update_response_action(
    incident_id: str,
    action_id: str,
    update: ResponseActionUpdate,
):
    allowed_transitions = {
        "PENDING": {"IN_PROGRESS", "FAILED"},
        "IN_PROGRESS": {"COMPLETED", "FAILED"},
        "COMPLETED": set(),
        "FAILED": set(),
    }

    with get_connection() as connection:
        incident = connection.execute(
            "SELECT incident_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        action = connection.execute(
            """
            SELECT action_id, status
            FROM response_actions
            WHERE action_id = ? AND incident_id = ?
            """,
            (action_id, incident_id),
        ).fetchone()

        if action is None:
            raise HTTPException(
                status_code=404,
                detail="Response action not found",
            )

        current_status = action["status"]
        new_status = update.status

        if new_status not in allowed_transitions.get(
            current_status,
            set(),
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Cannot transition response action "
                    f"from {current_status} to {new_status}"
                ),
            )

        connection.execute(
            """
            UPDATE response_actions
            SET status = ?, result = ?
            WHERE action_id = ? AND incident_id = ?
            """,
            (
                new_status,
                update.result,
                action_id,
                incident_id,
            ),
        )

            # Record the response-action status change.
        connection.execute(
            """
            INSERT INTO incident_events (
                event_id,
                incident_id,
                event_type,
                description
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                f"EVT-{uuid4().hex[:8]}",
                incident_id,
                "RESPONSE_STATUS_CHANGED",
                (
                    f"Response action {action_id} changed "
                    f"from {current_status} to {new_status}."
                ),
            ),
        )
        updated_action = connection.execute(
            """
            SELECT
                action_id,
                incident_id,
                action,
                target,
                status,
                result,
                created_at
            FROM response_actions
            WHERE action_id = ? AND incident_id = ?
            """,
            (action_id, incident_id),
        ).fetchone()

    return dict(updated_action)
@app.post("/webhook/edr")
def receive_edr_alert(
    alert: EDRAlert,
    x_webhook_secret: str = Header(...),
):
    # Authenticate the incoming webhook.
    if x_webhook_secret != WEBHOOK_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook authentication",
        )

    severity = alert.severity.strip().lower()

    indicators = extract_indicators(alert)
    playbook = select_playbook(severity)

    containment = None
    containment_result = None
    account_action = None

    if severity in ["critical", "high"]:
        status = "RESPONSE_REQUIRED"

        containment = contain_host(alert.hostname)
        containment_result = execute_containment(containment)
        account_action = suspend_account(alert.user)
    else:
        status = "MONITOR"

    incident = Incident(
        incident_id=f"INC-{uuid4().hex[:8]}",
        alert_id=alert.alert_id,
        severity=severity,
        hostname=alert.hostname,
        ip=alert.ip,
        user=alert.user,
        process=alert.process,
        sha256=alert.sha256,
        status=status,
    )

    # Persist the incident in SQLite.
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id,
                alert_id,
                severity,
                hostname,
                ip,
                user,
                process,
                sha256,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.incident_id,
                incident.alert_id,
                incident.severity,
                incident.hostname,
                incident.ip,
                incident.user,
                incident.process,
                incident.sha256,
                incident.status,
            ),
        )

    # Record the incident creation event.
    log_incident_event(
        incident_id=incident.incident_id,
        event_type="INCIDENT_CREATED",
        description=(
            f"Incident created from EDR alert "
            f"{incident.alert_id} with severity "
            f"{incident.severity}."
        ),
    )


    # Prepare the response action logs.
    response_action_logs = []

    if containment is not None and containment_result is not None:
        response_action_logs.append(
            ResponseActionLog(
                incident_id=incident.incident_id,
                action=containment.action,
                target=containment.hostname,
                status=containment.status,
                result=containment_result.result,
            )
        )

    if account_action is not None:
        response_action_logs.append(
            ResponseActionLog(
                incident_id=incident.incident_id,
                action=account_action.action,
                target=account_action.username,
                status=account_action.status,
                result=account_action.result,
            )
        )

    if response_action_logs:
        with get_connection() as connection:
            for action_log in response_action_logs:
                connection.execute(
                    """
                    INSERT INTO response_actions (
                        action_id,
                        incident_id,
                        action,
                        target,
                        status,
                        result
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"ACT-{uuid4().hex[:8]}",
                        action_log.incident_id,
                        action_log.action,
                        action_log.target,
                        action_log.status,
                        action_log.result,
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO incident_events (
                        event_id,
                        incident_id,
                        event_type,
                        description
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        f"EVT-{uuid4().hex[:8]}",
                        action_log.incident_id,
                        "RESPONSE_ACTION_CREATED",
                        (
                            f"Response action {action_log.action} "
                            f"created for target {action_log.target} "
                            f"with status {action_log.status}."
                        ),
                    ),
                )
            connection.commit()


    return {
        "message": "EDR alert received and incident created",
        "incident": incident,
        "extracted_indicators": indicators,
        "playbook": playbook,
        "containment_action": containment,
        "containment_result": containment_result,
        "account_action": account_action,
        "response_action_logs": response_action_logs,
    }