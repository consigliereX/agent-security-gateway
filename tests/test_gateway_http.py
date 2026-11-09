import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.controls import GatewayRuntimeConfig


class GatewayHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "session_state.sqlite3")
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

    def test_health(self) -> None:
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_ready(self) -> None:
        resp = self.client.get("/ready")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "ready")
        self.assertTrue(body["details"]["session_store"])

    def test_approval_submit_and_resolve_endpoints(self) -> None:
        submit = self.client.post(
            "/approval/submit",
            json={
                "session_id": "s1",
                "turn_id": "t1",
                "agent_id": "a1",
                "action_type": "exec_shell",
                "action_target": "cmd /c echo hello",
            },
        )
        self.assertEqual(submit.status_code, 200)
        approval_id = submit.json()["approval_id"]

        resolve = self.client.post(
            "/approval/resolve",
            headers={"x-api-key": "operator-test-key"},
            json={
                "approval_id": approval_id,
                "approve": True,
                "resolver": "ops",
                "note": "ok",
                "permit_ttl_seconds": 120,
            },
        )
        self.assertEqual(resolve.status_code, 200)
        body = resolve.json()
        self.assertEqual(body["status"], "approved")
        self.assertTrue(body["permit_token"])

    def test_tool_call_can_require_approval(self) -> None:
        resp = self.client.post(
            "/inspect/tool-call",
            json={
                "session_id": "s-1",
                "agent_id": "a-1",
                "tool_name": "exec_shell",
                "tool_target": "dir",
                "user_input": "run this",
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn(body["decision"], {"require_approval", "block"})
        if body["decision"] == "require_approval":
            self.assertIn("approval", body)

    def test_operator_overview_endpoint(self) -> None:
        self.client.post(
            "/inspect/tool-call",
            json={
                "session_id": "s-9",
                "agent_id": "a-9",
                "tool_name": "exec_shell",
                "tool_target": "cmd /c whoami",
                "user_input": "run this",
            },
        )
        overview = self.client.get("/operator/api/overview?limit=10", headers={"x-api-key": "operator-test-key"})
        self.assertEqual(overview.status_code, 200)
        body = overview.json()
        self.assertIn("sessions", body)
        self.assertIn("events_flagged", body)
        self.assertGreaterEqual(len(body["sessions"]), 1)

    def test_metrics_endpoint(self) -> None:
        self.client.get("/health")
        self.client.post(
            "/inspect/tool-call",
            json={"tool_name": "read_filesystem", "tool_target": "x", "user_input": "read"},
        )
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("gateway_http_requests_total", resp.text)


class GatewayGuardsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "guard_state.sqlite3")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_auth_required_fails_closed(self) -> None:
        cfg = GatewayRuntimeConfig(auth_enabled=True, api_keys=("k1",))
        app = create_app(session_db_path=self.db_path, runtime_config=cfg)
        client = TestClient(app)
        try:
            denied = client.post(
                "/inspect/tool-call",
                json={"tool_name": "read_filesystem", "tool_target": "x", "user_input": "read"},
            )
            self.assertEqual(denied.status_code, 401)

            ok = client.post(
                "/inspect/tool-call",
                headers={"x-api-key": "k1"},
                json={"tool_name": "read_filesystem", "tool_target": "x", "user_input": "read"},
            )
            self.assertEqual(ok.status_code, 200)
        finally:
            client.close()
            app.state.audit_store.close()
            app.state.approval_store.close()
            app.state.session_store.close()

    def test_auth_covers_operator_approval_and_metrics_endpoints(self) -> None:
        cfg = GatewayRuntimeConfig(auth_enabled=True, api_keys=("k1",), operator_api_keys=("ops-key",))
        app = create_app(session_db_path=self.db_path, runtime_config=cfg)
        client = TestClient(app)
        try:
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/ready").status_code, 200)

            self.assertEqual(client.get("/operator/api/overview").status_code, 401)
            self.assertEqual(client.get("/metrics").status_code, 401)
            self.assertEqual(
                client.post(
                    "/approval/submit",
                    json={"session_id": "s1", "action_type": "exec_shell", "action_target": "cmd /c whoami"},
                ).status_code,
                401,
            )

            self.assertEqual(
                client.get("/operator/api/overview", headers={"x-api-key": "k1"}).status_code,
                403,
            )
            self.assertEqual(client.get("/operator/api/overview", headers={"x-api-key": "ops-key"}).status_code, 200)
            self.assertEqual(client.get("/metrics", headers={"x-api-key": "k1"}).status_code, 200)
            self.assertEqual(
                client.post(
                    "/approval/submit",
                    headers={"x-api-key": "k1"},
                    json={"session_id": "s1", "action_type": "exec_shell", "action_target": "cmd /c whoami"},
                ).status_code,
                200,
            )
        finally:
            client.close()
            app.state.audit_store.close()
            app.state.approval_store.close()
            app.state.session_store.close()

    def test_rate_limit_deterministic(self) -> None:
        t = {"now": 1000.0}

        def now_fn() -> float:
            return t["now"]

        cfg = GatewayRuntimeConfig(rate_limit_enabled=True, rate_limit_requests=2, rate_limit_window_seconds=60)
        app = create_app(session_db_path=self.db_path, runtime_config=cfg, rate_limiter_now_fn=now_fn)
        client = TestClient(app)
        try:
            for _ in range(2):
                r = client.post(
                    "/inspect/tool-call",
                    json={"tool_name": "read_filesystem", "tool_target": "x", "user_input": "read"},
                )
                self.assertEqual(r.status_code, 200)

            blocked = client.post(
                "/inspect/tool-call",
                json={"tool_name": "read_filesystem", "tool_target": "x", "user_input": "read"},
            )
            self.assertEqual(blocked.status_code, 429)

            t["now"] += 61.0
            reset = client.post(
                "/inspect/tool-call",
                json={"tool_name": "read_filesystem", "tool_target": "x", "user_input": "read"},
            )
            self.assertEqual(reset.status_code, 200)
        finally:
            client.close()
            app.state.audit_store.close()
            app.state.approval_store.close()
            app.state.session_store.close()


if __name__ == "__main__":
    unittest.main()
