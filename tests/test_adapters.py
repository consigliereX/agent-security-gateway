import tempfile
import unittest
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

from firewall.adapters import (
    AdapterContext,
    FileSystemAdapter,
    HttpAdapter,
    MemoryAdapter,
    ShellAdapter,
    ToolExecutionDenied,
)


class StubService:
    def __init__(self, decisions: List[str]) -> None:
        self.decisions = list(decisions)
        self.calls: List[Dict[str, Any]] = []

    def inspect(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append(dict(kwargs))
        decision = self.decisions.pop(0) if self.decisions else "allow"
        return {
            "decision": decision,
            "total_score": 0.0,
            "reasons": [decision],
            "request_id": "req-1",
            "decided_at": "2026-01-01T00:00:00+00:00",
            "metadata": {},
            "findings": [],
            "session_id": kwargs.get("session_id", ""),
            "turn_id": kwargs.get("turn_id", ""),
            "agent_id": kwargs.get("agent_id", ""),
        }


class RedactingStubService(StubService):
    def sanitize_output(self, raw_output: str) -> Tuple[str, Dict[str, Any]]:
        masked = raw_output.replace("SECRET123", "[REDACTED:secret:abc123]")
        redacted = masked != raw_output
        return masked, {
            "redacted": redacted,
            "masked_count": 1 if redacted else 0,
            "items": [{"kind": "secret", "digest": "abc123", "length": 9}] if redacted else [],
        }


class AdaptersTests(unittest.TestCase):
    def test_shell_blocked_does_not_execute(self) -> None:
        svc = StubService(["block"])
        adapter = ShellAdapter(service=svc, allowed_executables=[sys.executable])
        ctx = AdapterContext(session_id="s1", user_input="run shell")

        with self.assertRaises(ToolExecutionDenied):
            adapter.run([sys.executable, "-c", "print('hello')"], ctx)

        self.assertEqual(len(svc.calls), 1)

    def test_shell_allowed_executes_and_posts(self) -> None:
        svc = StubService(["allow", "allow"])
        adapter = ShellAdapter(service=svc, allowed_executables=[sys.executable])
        ctx = AdapterContext(session_id="s1", user_input="run shell")

        proc = adapter.run([sys.executable, "-c", "print('hello')"], ctx)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("hello", proc.stdout.lower())
        self.assertEqual(len(svc.calls), 2)

    def test_filesystem_challenge_does_not_write(self) -> None:
        svc = StubService(["challenge"])
        with tempfile.TemporaryDirectory() as td:
            adapter = FileSystemAdapter(service=svc, base_dir=td)
            ctx = AdapterContext(session_id="s1", user_input="write file")
            p = Path(td) / "a.txt"

            with self.assertRaises(ToolExecutionDenied):
                adapter.write_text("a.txt", "secret", ctx)

            self.assertFalse(p.exists())
            self.assertEqual(len(svc.calls), 1)

    def test_filesystem_allowed_write_and_read(self) -> None:
        svc = StubService(["allow", "allow", "allow", "allow"])
        with tempfile.TemporaryDirectory() as td:
            adapter = FileSystemAdapter(service=svc, base_dir=td)
            ctx = AdapterContext(session_id="s1", user_input="rw")

            adapter.write_text("a.txt", "hello", ctx)
            out = adapter.read_text("a.txt", ctx)
            self.assertEqual(out, "hello")
            self.assertEqual(len(svc.calls), 4)

    def test_memory_blocked_does_not_write(self) -> None:
        svc = StubService(["block"])
        adapter = MemoryAdapter(service=svc)
        ctx = AdapterContext(session_id="s1", user_input="write memory")

        with self.assertRaises(ToolExecutionDenied):
            adapter.write("vault/key", "x", ctx)

        self.assertIsNone(adapter.read("vault/key", AdapterContext(session_id="s1", user_input="read")))

    def test_http_allowed_calls_urlopen(self) -> None:
        svc = StubService(["allow", "allow"])
        adapter = HttpAdapter(service=svc, allowed_hosts=["localhost"])
        ctx = AdapterContext(session_id="s1", user_input="http")

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return b"ok"

        with patch("firewall.adapters.url_request.urlopen", return_value=_Resp()) as mocked:
            out = adapter.request("GET", "http://localhost/test", ctx)
            self.assertEqual(out, "ok")
            mocked.assert_called_once()
            self.assertEqual(len(svc.calls), 2)

    def test_read_result_uses_central_redaction_pipeline(self) -> None:
        svc = RedactingStubService(["allow", "allow"])
        adapter = MemoryAdapter(service=svc, initial={"vault/key": "SECRET123"})
        ctx = AdapterContext(session_id="s1", user_input="read memory")

        value = adapter.read("vault/key", ctx)
        self.assertEqual(value, "[REDACTED:secret:abc123]")
        self.assertEqual(len(svc.calls), 2)
        self.assertEqual(svc.calls[1]["model_output"], "[REDACTED:secret:abc123]")
        self.assertTrue(svc.calls[1]["redaction"]["redacted"])


if __name__ == "__main__":
    unittest.main()
