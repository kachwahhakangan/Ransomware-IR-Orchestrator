from fastapi import FastAPI
from pydantic import BaseModel
from uuid import uuid4

app = FastAPI(
    title="Ransomware IR Orchestrator",
    description="Automated ransomware containment and incident response platform",
    version="0.1.0"
)


class EDRAlert(BaseModel):
    alert_id: str
    severity: str
    hostname: str
    ip: str
    user: str
    process: str
    sha256: str
    
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


@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational"
    }
@app.post("/webhook/edr")
def receive_edr_alert(alert: EDRAlert):
    severity = alert.severity.lower()

    if severity in ["critical", "high"]:
        status = "RESPONSE_REQUIRED"
    else:
        status = "MONITOR"

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
    }