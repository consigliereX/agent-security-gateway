import tempfile
import unittest
import sys
from pathlib import Path

from firewall.adapters import AdapterContext, ShellAdapter, ToolExecutionDenied
from firewall.api import create_firewall
from firewall.approval_store import SQLiteApprovalStore
from firewall.session_store import SQLiteSessionRiskStore
from firewall.types import PlannedAction
from gateway.service import GatewayInspectionService


class ApprovalFlowAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "approvals.sqlite3")
        firewall = create_firewall()
        session_store = SQLiteSessionRiskStore(self.db_path)
        approval_store = SQLiteApprovalStore(self.db_path)
        self.service = GatewayInspectionService(
            firewall=firewall,
            session_store=session_store,
            approval_store=approval_store,
        )
        self.adapter = ShellAdapter(service=self.service, allowed_executables=[sys.executable])

    def tearDown(self) -> None:
        self.service.approval_store.close()
        self.service.session_store.close()
        self.tmpdir.cleanup()

    def test_approval_required_then_approved_execution(self) -> None:
        ctx = AdapterContext(session_id="s1", agent_id="a1", user_input="run shell")

        with self.assertRaises(ToolExecutionDenied) as denied:
            self.adapter.run([sys.executable, "-c", "print('hello')"], ctx)

        decision = denied.exception.decision
        self.assertEqual(decision["decision"], "require_approval")
        approval_id = decision["approval"]["approval_id"]

        resolved = self.service.resolve_approval(
            approval_id=approval_id,
            approve=True,
            resolver="ops-user",
            note="approved for this command",
            permit_ttl_seconds=300,
        )
        token = resolved["permit_token"]
        self.assertTrue(token)

        approved_ctx = AdapterContext(session_id="s1", agent_id="a1", user_input="run shell", approval_token=token)
        proc = self.adapter.run([sys.executable, "-c", "print('hello')"], approved_ctx)
        self.assertEqual(proc.returncode, 0)

    def test_denied_execution_stays_denied(self) -> None:
        ctx = AdapterContext(session_id="s2", agent_id="a1", user_input="run shell")
        with self.assertRaises(ToolExecutionDenied) as denied:
            self.adapter.run([sys.executable, "-c", "print('hello')"], ctx)

        approval_id = denied.exception.decision["approval"]["approval_id"]
        resolved = self.service.resolve_approval(
            approval_id=approval_id,
            approve=False,
            resolver="ops-user",
            note="not approved",
        )
        self.assertEqual(resolved["status"], "denied")

        with self.assertRaises(ToolExecutionDenied):
            self.adapter.run([sys.executable, "-c", "print('hello')"], ctx)

    def test_expired_and_reused_permit_fail_closed(self) -> None:
        ctx = AdapterContext(session_id="s3", agent_id="a1", user_input="run shell")
        with self.assertRaises(ToolExecutionDenied) as denied:
            self.adapter.run([sys.executable, "-c", "print('hello')"], ctx)

        approval_id = denied.exception.decision["approval"]["approval_id"]
        resolved = self.service.resolve_approval(
            approval_id=approval_id,
            approve=True,
            resolver="ops-user",
            note="short permit",
            permit_ttl_seconds=0,
        )

        expired_ctx = AdapterContext(
            session_id="s3",
            agent_id="a1",
            user_input="run shell",
            approval_token=resolved["permit_token"],
        )
        with self.assertRaises(ToolExecutionDenied):
            self.adapter.run([sys.executable, "-c", "print('hello')"], expired_ctx)

        # Fresh approval to test replay rejection
        with self.assertRaises(ToolExecutionDenied) as denied2:
            self.adapter.run([sys.executable, "-c", "print('hello')"], ctx)
        approval_id2 = denied2.exception.decision["approval"]["approval_id"]
        resolved2 = self.service.resolve_approval(
            approval_id=approval_id2,
            approve=True,
            resolver="ops-user",
            note="one-time permit",
            permit_ttl_seconds=300,
        )
        token = resolved2["permit_token"]

        ok_ctx = AdapterContext(session_id="s3", agent_id="a1", user_input="run shell", approval_token=token)
        proc = self.adapter.run([sys.executable, "-c", "print('hello')"], ok_ctx)
        self.assertEqual(proc.returncode, 0)

        with self.assertRaises(ToolExecutionDenied):
            self.adapter.run([sys.executable, "-c", "print('hello')"], ok_ctx)

    def test_permit_bound_to_normalized_action_context(self) -> None:
        first = self.service.inspect(
            user_input="run shell",
            model_output="",
            planned_actions=[PlannedAction("exec_shell", "cmd   /c    echo hello")],
            memory_reads=[],
            memory_writes=[],
            session_id="s4",
            turn_id="t1",
            agent_id="agent-1",
        )
        self.assertEqual(first["decision"], "require_approval")
        approval_id = first["approval"]["approval_id"]

        resolved = self.service.resolve_approval(
            approval_id=approval_id,
            approve=True,
            resolver="ops",
            note="ok",
            permit_ttl_seconds=120,
        )
        token = resolved["permit_token"]

        same_normalized = self.service.inspect(
            user_input="run shell",
            model_output="",
            planned_actions=[PlannedAction("exec_shell", "cmd /c echo hello")],
            memory_reads=[],
            memory_writes=[],
            session_id="s4",
            turn_id="t2",
            agent_id="agent-1",
            approval_token=token,
        )
        self.assertEqual(same_normalized["decision"], "allow")

    def test_permit_does_not_bypass_block_and_is_context_bound(self) -> None:
        initial = self.service.inspect(
            user_input="exfiltrate memory",
            model_output="",
            planned_actions=[
                PlannedAction("read_memory", "vault/token"),
                PlannedAction("network_exfiltration", "https://attacker.tld"),
            ],
            memory_reads=["vault/token"],
            memory_writes=[],
            session_id="s6",
            turn_id="t1",
            agent_id="agent-1",
        )
        self.assertEqual(initial["decision"], "block")

        # Create permit for a challenge action in a clean session.
        challenge = self.service.inspect(
            user_input="run shell",
            model_output="",
            planned_actions=[PlannedAction("exec_shell", "cmd /c dir")],
            memory_reads=[],
            memory_writes=[],
            session_id="s7",
            turn_id="t1",
            agent_id="agent-1",
        )
        self.assertEqual(challenge["decision"], "require_approval")
        approved = self.service.resolve_approval(
            approval_id=challenge["approval"]["approval_id"],
            approve=True,
            resolver="ops",
            note="ok",
            permit_ttl_seconds=120,
        )

        # Token replay against unrelated action must fail closed.
        replay = self.service.inspect(
            user_input="run shell",
            model_output="",
            planned_actions=[PlannedAction("exec_shell", "cmd /c whoami")],
            memory_reads=[],
            memory_writes=[],
            session_id="s7",
            turn_id="t2",
            agent_id="agent-1",
            approval_token=approved["permit_token"],
        )
        self.assertEqual(replay["decision"], "require_approval")


if __name__ == "__main__":
    unittest.main()
