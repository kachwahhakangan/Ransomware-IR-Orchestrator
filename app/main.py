from fastapi import FastAPI
from pydantic import BaseModel

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


@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational"
    }


@app.post("/webhook/edr")
def receive_edr_alert(alert: EDRAlert):
    return {
        "message": "EDR alert validated and processed",
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "hostname": alert.hostname,
        "ip": alert.ip,
        "user": alert.user,
        "process": alert.process,
        "sha256": alert.sha256
    }