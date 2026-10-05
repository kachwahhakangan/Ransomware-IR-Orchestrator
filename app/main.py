from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from uuid import uuid4


app = FastAPI(
    title="Ransomware IR Orchestrator",
    description="Automated ransomware containment and incident response platform",
    version="0.1.0"
)

WEBHOOK_SECRET = "dev-edr-secret-123"


class EDRAlert(BaseModel):
    alert_id: str
    severity: str
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


def extract_indicators(alert: EDRAlert) -> AlertIndicators:
    return AlertIndicators(
        hostname=alert.hostname,
        ip=alert.ip,
        user=alert.user,
        process=alert.process,
        sha256=alert.sha256
    )


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


def contain_host(hostname: str) -> ContainmentAction:
    return ContainmentAction(
        action="NETWORK_ISOLATION",
        hostname=hostname,
        status="REQUESTED",
        management_connection="MAINTAINED"
    )


@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational"
    }


@app.post("/webhook/edr")
def receive_edr_alert(
    alert: EDRAlert,
    x_webhook_secret: str = Header(...)
):
    if x_webhook_secret != WEBHOOK_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook authentication"
        )

    severity = alert.severity.lower()

    if severity in ["critical", "high"]:
        status = "RESPONSE_REQUIRED"
        containment = contain_host(alert.hostname)
    else:
        status = "MONITOR"
        containment = None

    indicators = extract_indicators(alert)

    incident = Incident(
        incident_id=f"INC-{uuid4().hex[:8]}",
        alert_id=alert.alert_id,
        severity=alert.severity,
        hostname=alert.hostname,
        ip=alert.ip,
        user=alert.user,
        process=alert.process,
        sha256=alert.sha256,
        status=status,
    )

    return {
        "message": "EDR alert received and incident created",
        "incident": incident,
        "extracted_indicators": indicators,
        "containment_action": containment,
    }