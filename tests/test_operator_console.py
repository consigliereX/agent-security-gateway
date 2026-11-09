import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.controls import GatewayRuntimeConfig


class OperatorConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "gateway.sqlite3")
        self.app = create_app(session_db_path=self.db_path, runtime_config=GatewayRuntimeConfig(operator_api_keys=("operator-test-key",)))
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        try:
            self.app.state.audit_store.close()
        except Exception:
            pass
        try:
            self.app.state.approval_store.close()
        except Exception:
            pass
        try:
            self.app.state.session_store.close()
        except Exception:
            pass
        self.client.close()
        self.tmpdir.cleanup()

    def _seed_events(self) -> None:
        # event that should trigger approval queue + flagged event
        self.client.post(
            "/inspect/tool-call",
            json={
                "session_id": "sess-console-1",
                "turn_id": "t-1",
                "agent_id": "agent-1",
                "tool_name": "exec_shell",
                "tool_target": "cmd /c whoami",
                "user_input": "run this",
            },
        )
        # lower risk event in another session
        self.client.post(
            "/inspect/tool-call",
            json={
                "session_id": "sess-console-2",
                "turn_id": "t-1",
                "agent_id": "agent-2",
                "tool_name": "read_filesystem",
                "tool_target": "notes.txt",
                "user_input": "read file",
            },
        )

    def test_operator_overview_has_sessions_and_flagged_events(self) -> None:
        self._seed_events()
        resp = self.client.get("/operator/api/overview?limit=20", headers={"x-api-key": "operator-test-key"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()

        self.assertIn("sessions", body)
        self.assertIn("approvals_pending", body)
        self.assertIn("events_flagged", body)
        self.assertGreaterEqual(len(body["sessions"]), 1)
        self.assertGreaterEqual(len(body["events_flagged"]), 1)

        for event in body["events_flagged"]:
            self.assertIn(event["decision"], {"block", "challenge", "require_approval"})

    def test_operator_session_timeline_endpoint(self) -> None:
        self._seed_events()
        resp = self.client.get("/operator/api/session/sess-console-1/timeline", headers={"x-api-key": "operator-test-key"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["session_id"], "sess-console-1")
        self.assertGreaterEqual(len(body["timeline"]), 1)
        self.assertTrue(all(item["session_id"] == "sess-console-1" for item in body["timeline"]))

    def test_operator_console_html_renders(self) -> None:
        self._seed_events()
        resp = self.client.get("/operator?session_id=sess-console-1", headers={"x-api-key": "operator-test-key"})
        self.assertEqual(resp.status_code, 200)
        text = resp.text
        self.assertIn("Agent Security Gateway Operator Console", text)
        self.assertIn("Blocked/Challenged Events", text)


if __name__ == "__main__":
    unittest.main()
