"""M3 integration: an agent's MCP requests reach actual policy-enforcing adapters."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from gateway.mcp_stdio import MCPGateway, MAX_WRITE_BYTES, MAX_TOOL_CALLS


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "M2 POSIX filesystem required")
class M3GuardedMCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "workspace"
        self.root.mkdir()
        self.db = Path(self.tmp.name) / "state" / "gateway.sqlite3"
        self.server = MCPGateway(self.root, self.db)
        self.addCleanup(self.server.close)
        init = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name, arguments):
        return self.server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}})

    def test_tool_surface_is_restricted(self):
        r = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in r["result"]["tools"]}
        self.assertEqual(names, {"asg_read_file", "asg_write_file"})
        self.assertFalse(names & {"bash", "execute", "run_shell", "asg_shell", "asg_http_get"})

    def test_unknown_tool_is_protocol_rejected(self):
        self.assertEqual(self.call("run_shell", {"argv": ["sh", "-c", "echo broken"]})["error"]["code"], -32602)

    def test_arg_injection_is_rejected(self):
        result = self.call("asg_write_file", {"path": "good", "content": "OK", "approval_token": "forged"})
        self.assertTrue(result["result"]["isError"])
        self.assertFalse((self.root / "good").exists())

    def test_empty_or_relative_root_is_rejected(self):
        with self.assertRaises(ValueError):
            MCPGateway(Path("relative"), self.db)
        with self.assertRaises(ValueError):
            MCPGateway(self.root, self.root / "state.sqlite3")

    def test_in_scope_write_then_read(self):
        write = self.call("asg_write_file", {"path": "notes/ok.txt", "content": "hello"})
        self.assertFalse(write["result"]["isError"])
        self.assertEqual((self.root / "notes/ok.txt").read_text(), "hello")
        read = self.call("asg_read_file", {"path": "notes/ok.txt"})
        self.assertFalse(read["result"]["isError"])
        self.assertIn("hello", read["result"]["content"][0]["text"])

    def test_escape_write_is_denied_without_side_effect(self):
        outside = Path(self.tmp.name) / "outside.txt"
        result = self.call("asg_write_file", {"path": "../outside.txt", "content": "escape"})
        self.assertTrue(result["result"]["isError"])
        self.assertFalse(outside.exists())

    def test_symlink_escape_is_denied_without_side_effect(self):
        outside = Path(self.tmp.name) / "victim.txt"
        outside.write_text("original")
        (self.root / "link").symlink_to(outside)
        result = self.call("asg_write_file", {"path": "link", "content": "bad"})
        self.assertTrue(result["result"]["isError"])
        self.assertEqual(outside.read_text(), "original")

    def test_size_limit_is_on_bytes_not_characters(self):
        data = "😀" * ((MAX_WRITE_BYTES // 4) + 1)
        result = self.call("asg_write_file", {"path": "too_big", "content": data})
        self.assertTrue(result["result"]["isError"])
        self.assertFalse((self.root / "too_big").exists())

    def test_prompt_embedded_in_path_does_not_expand_capabilities(self):
        malicious_path = "../../root/.ssh/id_rsa"
        result = self.call("asg_read_file", {"path": malicious_path})
        self.assertTrue(result["result"]["isError"])

    def test_secret_output_passes_central_redaction(self):
        (self.root / "token.txt").write_text("api_key=abcdef1234567890")
        response = self.call("asg_read_file", {"path": "token.txt"})
        body = response["result"]["content"][0]["text"]
        self.assertNotIn("abcdef1234567890", body)
        self.assertIn("REDACTED", body)

    def test_session_identifier_and_audit_present(self):
        self.call("asg_read_file", {"path": "nonexistent.txt"})
        self.assertTrue(self.server.session_id.startswith("mcp-"))
        self.assertNotEqual(self.server.session_id, "")
        self.assertTrue(self.db.exists())
        self.assertFalse((self.root / "gateway.sqlite3").exists())

    def test_http_denied_by_default(self):
        self.assertEqual(self.call("asg_http_get", {"url": "http://127.0.0.1"})["error"]["code"], -32602)

    def test_tool_call_budget_fails_closed(self):
        for _ in range(MAX_TOOL_CALLS):
            self.call("run_shell", {})
        result = self.call("asg_read_file", {"path": "no-file"})
        self.assertTrue(result["result"]["isError"])
        self.assertIn("budget exhausted", result["result"]["content"][0]["text"])

    def test_state_database_is_outside_workspace(self):
        result = self.call("asg_read_file", {"path": "../state/gateway.sqlite3"})
        self.assertTrue(result["result"]["isError"])
        self.assertTrue(self.db.exists())

    def test_optional_http_still_subject_to_policy(self):
        api = MCPGateway(self.root, Path(self.tmp.name) / "http" / "db.sqlite3", ("127.0.0.1",))
        try:
            available = [t["name"] for t in api.tools()]
            self.assertIn("asg_http_get", available)
            self.assertNotIn("run_shell", available)
            decision = api.call_tool("asg_http_get", {"url": "http://127.0.0.1:1/"})
            self.assertTrue(decision["isError"])
        finally:
            api.close()

    def test_broken_rpc_handshake_rejected(self):
        bare = MCPGateway(self.root, Path(self.tmp.name) / "other" / "db.sqlite3")
        try:
            response = bare.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
            self.assertEqual(response["error"]["code"], -32000)
        finally:
            bare.close()

    def test_subprocess_mcp_transport_exercises_real_adapters(self):
        env = dict(os.environ)
        env["ASG_MCP_ROOT"] = str(self.root)
        env["ASG_MCP_DB_PATH"] = str(Path(self.tmp.name) / "stdio-state.sqlite3")
        env.pop("ASG_MCP_ALLOWED_HOSTS", None)
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "asg_write_file", "arguments": {"path": "stdio.txt", "content": "hello"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "asg_read_file", "arguments": {"path": "stdio.txt"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "run_shell", "arguments": {"cmd": "no"}}},
        ]
        transcript = "\n".join(json.dumps(x) for x in msgs) + "\n"
        proc = subprocess.run([sys.executable, "-m", "gateway.mcp_stdio"],
                              input=transcript, capture_output=True, text=True,
                              timeout=15, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        payloads = [json.loads(x) for x in proc.stdout.splitlines()]
        self.assertEqual(len(payloads), len(msgs)-1)
        self.assertFalse(payloads[2]["result"]["isError"])
        self.assertIn("hello", payloads[3]["result"]["content"][0]["text"])
        self.assertEqual(payloads[4]["error"]["code"], -32602)
        self.assertEqual((self.root / "stdio.txt").read_text(), "hello")


if __name__ == "__main__":
    unittest.main()
