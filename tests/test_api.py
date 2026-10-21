import unittest

from fastapi.testclient import TestClient

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


if __name__ == "__main__":
    unittest.main()
