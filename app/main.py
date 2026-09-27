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
    return {
        "message": "EDR alert received",
        "alert": alert
    }