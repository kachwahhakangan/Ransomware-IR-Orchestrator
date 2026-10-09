from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from uuid import uuid4


# Initialize FastAPI application
app = FastAPI(
    title="Ransomware IR Orchestrator",
    description="Automated ransomware containment and incident response platform",
    version="0.1.0"
)


# Development-only webhook secret
WEBHOOK_SECRET = "dev-edr-secret-123"


# Model for incoming EDR alerts
class EDRAlert(BaseModel):
    alert_id: str
    severity: str
    hostname: str
    ip: str
    user: str
    process: str
    sha256: str


# Model for extracted alert indicators
class AlertIndicators(BaseModel):
    hostname: str
    ip: str
    user: str
    process: str
    sha256: str


# Extract important indicators from an alert
def extract_indicators(alert: EDRAlert) -> AlertIndicators:
    return AlertIndicators(
        hostname=alert.hostname,
        ip=alert.ip,
        user=alert.user,
        process=alert.process,
        sha256=alert.sha256
    )


# Model for an incident
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


# Model for a network containment request
class ContainmentAction(BaseModel):
    action: str
    hostname: str
    status: str
    management_connection: str


# Model for an account action
class AccountAction(BaseModel):
    action: str
    username: str
    status: str
    result: str

# Model for recording response actions
class ResponseActionLog(BaseModel):
    incident_id: str
    action: str
    target: str
    status: str
    result: str


# Model for the containment execution result
class ContainmentResult(BaseModel):
    hostname: str
    action: str
    result: str
    management_connection: str


# Model for the selected response playbook
class ResponsePlaybook(BaseModel):
    name: str
    severity: str
    action: str
    status: str


# Create a simulated host containment request
def contain_host(hostname: str) -> ContainmentAction:
    return ContainmentAction(
        action="NETWORK_ISOLATION",
        hostname=hostname,
        status="REQUESTED",
        management_connection="MAINTAINED"
    )


# Simulate execution of a containment request
def execute_containment(
    action: ContainmentAction
) -> ContainmentResult:
    return ContainmentResult(
        hostname=action.hostname,
        action=action.action,
        result="SIMULATED_SUCCESS",
        management_connection=action.management_connection
    )


# Simulate account suspension
def suspend_account(username: str) -> AccountAction:
    return AccountAction(
        action="ACCOUNT_SUSPENSION",
        username=username,
        status="REQUESTED",
        result="SIMULATED_SUCCESS"
    )


# Select the appropriate response playbook
def select_playbook(severity: str) -> ResponsePlaybook:
    normalized = severity.strip().lower()

    if normalized in ["critical", "high"]:
        return ResponsePlaybook(
            name="RANSOMWARE_CONTAINMENT",
            severity=normalized.upper(),
            action="NETWORK_ISOLATION",
            status="READY"
        )

    return ResponsePlaybook(
        name="MONITORING",
        severity=normalized.upper(),
        action="NONE",
        status="NO_ACTION_REQUIRED"
    )


# Root endpoint
@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational"
    }


# Receive and process EDR alerts
@app.post("/webhook/edr")
def receive_edr_alert(
    alert: EDRAlert,
    x_webhook_secret: str = Header(...)
):

    # Authenticate the incoming webhook
    if x_webhook_secret != WEBHOOK_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook authentication"
        )

    # Normalize severity
    severity = alert.severity.strip().lower()

    # Extract indicators and select response playbook
    indicators = extract_indicators(alert)
    playbook = select_playbook(severity)

    # Execute response actions for high-risk alerts
    if severity in ["critical", "high"]:
        status = "RESPONSE_REQUIRED"

        # Simulate host network isolation
        containment = contain_host(alert.hostname)

        containment_result = execute_containment(containment)

        # Simulate account suspension
        account_action = suspend_account(alert.user)

    else:
        status = "MONITOR"
        containment = None
        containment_result = None
        account_action = None

    # Create the incident record
    incident = Incident(
        incident_id=f"INC-{uuid4().hex[:8]}",
        alert_id=alert.alert_id,
        severity=alert.severity,
        hostname=alert.hostname,
        ip=alert.ip,
        user=alert.user,
        process=alert.process,
        sha256=alert.sha256,
        status=status
    )

    # Create an audit log for each response action
    response_action_logs = []

    if containment is not None and containment_result is not None:
        response_action_logs.append(
            ResponseActionLog(
                incident_id=incident.incident_id,
                action=containment.action,
                target=containment.hostname,
                status=containment.status,
                result=containment_result.result
            )
        )

    if account_action is not None:
        response_action_logs.append(
            ResponseActionLog(
                incident_id=incident.incident_id,
                action=account_action.action,
                target=account_action.username,
                status=account_action.status,
                result=account_action.result
            )
        )


    response_action_logs = []

    if containment is not None and containment_result is not None:
        response_action_logs.append(
            ResponseActionLog(
                incident_id=incident.incident_id,
                action=containment.action,
                target=containment.hostname,
                status=containment.status,
                result=containment_result.result
            )
        )

    if account_action is not None:
        response_action_logs.append(
            ResponseActionLog(
                incident_id=incident.incident_id,
                action=account_action.action,
                target=account_action.username,
                status=account_action.status,
                result=account_action.result
            )
        )

    # Return the complete processing result
    return {
        "message": "EDR alert received and incident created",
        "incident": incident,
        "extracted_indicators": indicators,
        "playbook": playbook,
        "containment_action": containment,
        "containment_result": containment_result,
        "account_action": account_action,
        "response_action_logs": response_action_logs
    }
