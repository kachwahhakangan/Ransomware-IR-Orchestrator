from fastapi import FastAPI

app = FastAPI(
    title="Ransomware IR Orchestrator",
    description="Automated ransomware containment and incident response platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational"
    }
    from fastapi import FastAPI

app = FastAPI(
    title="Ransomware IR Orchestrator",
    description="Automated ransomware containment and incident response platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "Ransomware IR Orchestrator is running",
        "status": "operational"
    }
@app.post("/webhook/edr")
def receive_edr_alert(alert: dict):
    alert_id = alert.get("alert_id")
    severity = alert.get("severity")
    hostname = alert.get("hostname")
    ip = alert.get("ip")
    user = alert.get("user")
    process = alert.get("process")
    sha256 = alert.get("sha256")

    return {
        "message": "EDR alert processed",
        "alert_id": alert_id,
        "severity": severity,
        "hostname": hostname,
        "ip": ip,
        "user": user,
        "process": process,
        "sha256": sha256
    }