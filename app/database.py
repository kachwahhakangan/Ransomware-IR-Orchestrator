import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATA_DIR / "incidents.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                user TEXT NOT NULL,
                process TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                collection_status TEXT NOT NULL,
                sha256 TEXT,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents (incident_id)
                    ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS response_actions (
                action_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents (incident_id)
                    ON DELETE CASCADE
            )
        """)

        connection.commit()