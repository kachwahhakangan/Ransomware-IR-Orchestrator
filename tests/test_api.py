import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import get_connection
from app.main import app


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "message": "Ransomware IR Orchestrator is running",
                "status": "operational",
            },
        )

    def test_list_incidents(self):
        response = self.client.get("/incidents")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
    def test_incident_search_and_filtering(self):
        test_ids = [
            f"INC-FILTER-{uuid4().hex[:8]}"
            for _ in range(3)
        ]

        test_data = [
            (test_ids[0], "high", "RESPONSE_REQUIRED", "FILTER-PC-01"),
            (test_ids[1], "critical", "RESPONSE_REQUIRED", "FILTER-PC-02"),
            (test_ids[2], "low", "MONITOR", "OTHER-PC-01"),
        ]

        try:
            with get_connection() as connection:
                for incident_id, severity, status, hostname in test_data:
                    connection.execute(
                        """
                        INSERT INTO incidents (
                            incident_id, alert_id, severity, hostname,
                            ip, user, process, sha256, status
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            incident_id,
                            f"ALERT-{incident_id}",
                            severity,
                            hostname,
                            "192.168.1.10",
                            "test-user",
                            "test.exe",
                            "a" * 64,
                            status,
                        ),
                    )

            response = self.client.get(
                "/incidents",
                params={
                    "severity": "high",
                    "status": "RESPONSE_REQUIRED",
                    "hostname": "FILTER-PC",
                },
            )

            self.assertEqual(response.status_code, 200)
            results = response.json()

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["incident_id"], test_ids[0])

        finally:
            with get_connection() as connection:
                connection.executemany(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    [(incident_id,) for incident_id in test_ids],
                )

    def test_incident_statistics(self):
        response = self.client.get("/incidents/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_incidents", data)
        self.assertIn("critical_incidents", data)
        self.assertIn("high_incidents", data)
        self.assertIn("response_required", data)
        self.assertIn("monitoring", data)

    def test_nonexistent_incident(self):
        response = self.client.get("/incidents/INC-DOES-NOT-EXIST")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Incident not found")

    def test_invalid_edr_alert(self):
        response = self.client.post(
            "/webhook/edr",
            json={
                "alert_id": "TEST-INVALID-001",
                "severity": "extreme",
                "hostname": "TEST-PC",
                "ip": "192.168.1.100",
                "user": "test-user",
                "process": "test.exe",
                "sha256": "abc123",
            },
            headers={"X-Webhook-Secret": "dev-edr-secret-123"},
        )
        self.assertEqual(response.status_code, 422)
    def test_response_actions_for_existing_incident(self):
        incident_id = f"INC-TEST-{uuid4().hex[:8]}"
        action_id = f"ACT-TEST-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        "ALERT-TEST",
                        "high",
                        "TEST-PC",
                        "192.168.1.10",
                        "test-user",
                        "test.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, incident_id, action,
                        target, status, result
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        incident_id,
                        "NETWORK_ISOLATION",
                        "TEST-PC",
                        "SIMULATED",
                        "Test action recorded",
                    ),
                )

            response = self.client.get(
                f"/incidents/{incident_id}/response-actions"
            )

            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertEqual(data["incident_id"], incident_id)
            self.assertEqual(data["total_actions"], 1)
            self.assertEqual(
                data["response_actions"][0]["action"],
                "NETWORK_ISOLATION",
            )

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_response_actions_for_nonexistent_incident(self):
        incident_id = f"INC-MISSING-{uuid4().hex[:8]}"

        response = self.client.get(
            f"/incidents/{incident_id}/response-actions"
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json()["detail"],
            "Incident not found",
        )
    def test_update_response_action_status(self):
        incident_id = f"INC-TEST-{uuid4().hex[:8]}"
        action_id = f"ACT-TEST-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        f"ALERT-{uuid4().hex[:8]}",
                        "high",
                        "TEST-PC",
                        "192.168.1.10",
                        "test-user",
                        "test.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, incident_id, action,
                        target, status, result
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        incident_id,
                        "NETWORK_ISOLATION",
                        "TEST-PC",
                        "PENDING",
                        "Waiting to start",
                    ),
                )

            response = self.client.patch(
                f"/incidents/{incident_id}/response-actions/{action_id}",
                json={
                    "status": "IN_PROGRESS",
                    "result": "Action started in simulation",
                },
            )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "IN_PROGRESS")
            self.assertEqual(
                response.json()["result"],
                "Action started in simulation",
            )

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_reject_invalid_response_action_transition(self):
        incident_id = f"INC-TEST-{uuid4().hex[:8]}"
        action_id = f"ACT-TEST-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        f"ALERT-{uuid4().hex[:8]}",
                        "high",
                        "TEST-PC",
                        "192.168.1.10",
                        "test-user",
                        "test.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, incident_id, action,
                        target, status, result
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        incident_id,
                        "NETWORK_ISOLATION",
                        "TEST-PC",
                        "COMPLETED",
                        "Simulation completed",
                    ),
                )

            response = self.client.patch(
                f"/incidents/{incident_id}/response-actions/{action_id}",
                json={
                    "status": "PENDING",
                    "result": "Trying to reset status",
                },
            )

            self.assertEqual(response.status_code, 409)

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_update_nonexistent_response_action(self):
        incident_id = f"INC-TEST-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        f"ALERT-{uuid4().hex[:8]}",
                        "high",
                        "TEST-PC",
                        "192.168.1.10",
                        "test-user",
                        "test.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

            response = self.client.patch(
                f"/incidents/{incident_id}/response-actions/ACT-MISSING",
                json={
                    "status": "IN_PROGRESS",
                    "result": "Test update",
                },
            )

            self.assertEqual(response.status_code, 404)
            self.assertEqual(
                response.json()["detail"],
                "Response action not found",
            )

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_reject_invalid_response_action_status(self):
        incident_id = f"INC-TEST-{uuid4().hex[:8]}"
        action_id = f"ACT-TEST-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        f"ALERT-{uuid4().hex[:8]}",
                        "high",
                        "TEST-PC",
                        "192.168.1.10",
                        "test-user",
                        "test.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, incident_id, action,
                        target, status, result
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        incident_id,
                        "NETWORK_ISOLATION",
                        "TEST-PC",
                        "PENDING",
                        "Waiting to start",
                    ),
                )

            response = self.client.patch(
                f"/incidents/{incident_id}/response-actions/{action_id}",
                json={
                    "status": "UNKNOWN",
                    "result": "Invalid status test",
                },
            )

            self.assertEqual(response.status_code, 422)

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_incident_report_for_existing_incident(self):
        incident_id = f"INC-REPORT-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        f"ALERT-{uuid4().hex[:8]}",
                        "critical",
                        "REPORT-PC",
                        "192.168.1.50",
                        "test-user",
                        "suspicious.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO response_actions (
                        action_id, incident_id, action,
                        target, status, result
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"ACT-{uuid4().hex[:8]}",
                        incident_id,
                        "NETWORK_ISOLATION",
                        "REPORT-PC",
                        "COMPLETED",
                        "Isolation simulated successfully",
                    ),
                )

            response = self.client.get(
                f"/incidents/{incident_id}/report"
            )

            self.assertEqual(response.status_code, 200)

            report = response.json()

            self.assertEqual(report["incident_id"], incident_id)
            self.assertEqual(
                report["incident"]["hostname"],
                "REPORT-PC",
            )
            self.assertIn("evidence", report)
            self.assertIn("response_actions", report)
            self.assertIn("evidence_summary", report)
            self.assertIn("response_summary", report)

            self.assertEqual(
                report["response_summary"]["total"],
                len(report["response_actions"]),
            )
            self.assertEqual(
                report["response_summary"]["completed"],
                1,
            )

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_incident_report_for_nonexistent_incident(self):
        response = self.client.get(
            "/incidents/INC-REPORT-MISSING/report"
        )

        self.assertEqual(response.status_code, 404)


    def test_incident_timeline_for_existing_incident(self):
        incident_id = f"INC-TIMELINE-{uuid4().hex[:8]}"

        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, alert_id, severity, hostname,
                        ip, user, process, sha256, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        f"ALERT-{uuid4().hex[:8]}",
                        "high",
                        "TIMELINE-PC",
                        "192.168.1.20",
                        "test-user",
                        "test.exe",
                        "a" * 64,
                        "RESPONSE_REQUIRED",
                    ),
                )

                connection.execute(
                    """
                    INSERT INTO incident_events (
                        event_id, incident_id, event_type, description
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        f"EVT-{uuid4().hex[:8]}",
                        incident_id,
                        "INCIDENT_CREATED",
                        "Test incident created",
                    ),
                )

            response = self.client.get(
                f"/incidents/{incident_id}/timeline"
            )

            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertEqual(data["incident_id"], incident_id)
            self.assertEqual(data["total_events"], 1)
            self.assertEqual(
                data["timeline"][0]["event_type"],
                "INCIDENT_CREATED",
            )
            self.assertIn("created_at", data["timeline"][0])

        finally:
            with get_connection() as connection:
                connection.execute(
                    "DELETE FROM incidents WHERE incident_id = ?",
                    (incident_id,),
                )

    def test_incident_timeline_for_nonexistent_incident(self):
        response = self.client.get(
            "/incidents/INC-TIMELINE-MISSING/timeline"
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json()["detail"],
            "Incident not found",
        )
    def test_high_severity_webhook_records_timeline_events(self):
        incident_id = None

        try:
            response = self.client.post(
                "/webhook/edr",
                headers={
                    "X-Webhook-Secret": "dev-edr-secret-123"
                },
                json={
                    "alert_id": f"ALERT-TIMELINE-{uuid4().hex[:8]}",
                    "severity": "high",
                    "hostname": "TIMELINE-WEBHOOK-PC",
                    "ip": "192.168.1.50",
                    "user": "timeline-test-user",
                    "process": "suspicious.exe",
                    "sha256": "a" * 64,
                },
            )

            self.assertEqual(response.status_code, 200)

            incident_id = response.json()["incident"]["incident_id"]

            timeline_response = self.client.get(
                f"/incidents/{incident_id}/timeline"
            )

            self.assertEqual(timeline_response.status_code, 200)

            timeline = timeline_response.json()

            self.assertEqual(timeline["total_events"], 3)

            event_types = [
                event["event_type"]
                for event in timeline["timeline"]
            ]

            self.assertEqual(
                event_types.count("INCIDENT_CREATED"),
                1,
            )

            self.assertEqual(
                event_types.count("RESPONSE_ACTION_CREATED"),
                2,
            )

        finally:
            if incident_id is not None:
                with get_connection() as connection:
                    connection.execute(
                        "DELETE FROM incidents WHERE incident_id = ?",
                        (incident_id,),
                    )
if __name__ == "__main__":
    unittest.main()
