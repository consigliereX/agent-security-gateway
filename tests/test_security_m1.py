"""Security M1 regressions: authorization, exact argv, atomic permits."""
from __future__ import annotations
import json
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from firewall.adapters import AdapterContext, ShellAdapter
from firewall.approval_store import SQLiteApprovalStore
from firewall.detectors import SecretLeakDetector
from firewall.types import PlannedAction, SecurityContext
from gateway.app import create_app
from gateway.controls import GatewayRuntimeConfig


class _AllowService:
    def __init__(self):
        self.calls = []
    def inspect(self, **kwargs):
        self.calls.append(kwargs)
        return {"decision": "allow", "metadata": {}}


class EnforcementM1Tests(unittest.TestCase):
    def test_full_argv_is_inspected_and_executed(self):
        svc = _AllowService()
        adapter = ShellAdapter(service=svc, allowed_executables=["python"])
        argv = ["python", "-c", "print('safe')", "extra argument"]
        with patch("firewall.adapters.subprocess.run", return_value=subprocess.CompletedProcess(argv, 0, "ok", "")) as mock_run:
            adapter.run(argv, AdapterContext(session_id="s", agent_id="a"))
        inspected = json.loads(svc.calls[0]["planned_actions"][0].target)
        self.assertEqual(inspected, argv)
        self.assertEqual(mock_run.call_args.args[0], argv)
        self.assertEqual(json.loads(svc.calls[1]["planned_actions"][0].target), argv)

    def test_argv_boundaries_change_inspection_fingerprint(self):
        svc = _AllowService()
        adapter = ShellAdapter(service=svc, allowed_executables=["python"])
        for argv in (["python", "a b"], ["python", "a", "b"]):
            with patch("firewall.adapters.subprocess.run", return_value=subprocess.CompletedProcess(argv, 0, "", "")):
                adapter.run(argv, AdapterContext(session_id="s", agent_id="a"))
        self.assertNotEqual(svc.calls[0]["planned_actions"][0].target, svc.calls[2]["planned_actions"][0].target)

    def test_secret_leakage_inspects_action_target(self):
        action = PlannedAction("exec_shell", json.dumps(["python", "-c", "api_key=abcdef1234567890"]))
        findings = SecretLeakDetector().detect(SecurityContext(planned_actions=[action]))
        self.assertTrue(any(f.category == "secret_leakage" for f in findings))

    def test_operator_key_separation(self):
        cfg = GatewayRuntimeConfig(auth_enabled=True, api_keys=("agent-secret",), operator_api_keys=("operator-secret",))
        cfg.validate()
        with tempfile.TemporaryDirectory() as temp:
            app = create_app(session_db_path=str(Path(temp) / "gateway.sqlite3"), runtime_config=cfg)
            with TestClient(app) as client:
                submit = client.post("/approval/submit", headers={"x-api-key": "agent-secret"}, json={
                    "session_id": "s1", "agent_id": "agent-1", "action_type": "exec_shell", "action_target": "test"})
                self.assertEqual(submit.status_code, 200)
                payload = {"approval_id": submit.json()["approval_id"], "approve": True, "resolver": "ops", "note": "ok"}
                self.assertEqual(client.post("/approval/resolve", json=payload).status_code, 401)
                self.assertEqual(client.post("/approval/resolve", headers={"x-api-key": "agent-secret"}, json=payload).status_code, 403)
                self.assertEqual(client.get("/operator", headers={"x-api-key": "agent-secret"}).status_code, 403)
                self.assertEqual(client.post("/approval/resolve", headers={"x-api-key": "operator-secret"}, json=payload).status_code, 200)
                self.assertEqual(client.get("/operator", headers={"x-api-key": "operator-secret"}).status_code, 200)
                self.assertEqual(client.post("/inspect/tool-call", headers={"x-api-key": "agent-secret"}, json={
                    "tool_name": "read_filesystem", "tool_target": "hello"}).status_code, 200)
            for store in (app.state.audit_store, app.state.approval_store, app.state.session_store):
                store.close()

    def test_no_operator_key_fails_closed(self):
        cfg = GatewayRuntimeConfig(auth_enabled=False)
        with tempfile.TemporaryDirectory() as temp:
            app = create_app(session_db_path=str(Path(temp) / "gateway.sqlite3"), runtime_config=cfg)
            with TestClient(app) as client:
                self.assertEqual(client.get("/operator").status_code, 503)
                self.assertEqual(client.post("/approval/resolve", json={}).status_code, 503)
            for store in (app.state.audit_store, app.state.approval_store, app.state.session_store):
                store.close()

    def test_operator_and_agent_keys_cannot_overlap(self):
        with self.assertRaises(ValueError):
            GatewayRuntimeConfig(auth_enabled=True, api_keys=("same",), operator_api_keys=("same",)).validate()

    def test_atomic_permit_consumption(self):
        with tempfile.TemporaryDirectory() as td:
            store = SQLiteApprovalStore(str(Path(td) / "permits.sqlite3"))
            pending = store.get_or_create_pending(session_id="s", turn_id="t", agent_id="a", action_fingerprint="hash", action_type="exec_shell", action_target="echo")
            approved = store.resolve(approval_id=pending.approval_id, approve=True, resolver="ops", note="approved")
            barrier = threading.Barrier(8)
            def consume(_):
                barrier.wait()
                return store.consume_permit(permit_token=approved.permit_token, session_id="s", agent_id="a", action_fingerprint="hash")
            with ThreadPoolExecutor(max_workers=8) as pool:
                out = list(pool.map(consume, range(8)))
            self.assertEqual(sum(record is not None for record in out), 1)
            self.assertEqual(store.get(pending.approval_id).status, "used")
            store.close()

if __name__ == "__main__":
    unittest.main()
