"""M4 construction contracts. Live bwrap proof is scripts/m4_adversarial.py."""
from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gateway.os_sandbox import (
    SandboxUnavailable, _bwrap_binary, _minimal_env, _pump, _state_path,
    _workspace, build_command, run_child, run_mcp_bridge,
)


class SandboxM4UnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="asg-m4-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "workspace"
        self.root.mkdir()

    def command(self):
        return build_command(self.root, ["/usr/bin/python3", "/work/agent.py"], bwrap="/fake/bwrap")

    def test_namespace_invariants_and_fail_closed_user_ns(self):
        argv = self.command()
        self.assertIn("--unshare-all", argv)
        self.assertIn("--unshare-user", argv)
        self.assertIn("--disable-userns", argv)
        self.assertNotIn("--share-net", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--new-session", argv)
        self.assertIn("--cap-drop", argv)

    def test_ro_workspace_and_no_host_rw_mounts(self):
        argv = self.command()
        self.assertIn(["--ro-bind", str(self.root), "/work"],
                      [argv[i:i+3] for i in range(len(argv)-2)])
        self.assertNotIn("--bind", argv)
        self.assertNotIn("--dev-bind", argv)
        self.assertNotIn("--share-net", argv)
        self.assertNotIn(str(Path.home()), argv)
        self.assertNotIn("--ro-bind", argv[-3:])

    def test_private_tmpfs_has_size_and_permissions(self):
        cmd = self.command()
        self.assertIn(["--perms", "1777", "--size", "67108864", "--tmpfs", "/tmp"],
                      [cmd[i:i+6] for i in range(len(cmd)-5)])
        self.assertIn("--proc", cmd)
        self.assertIn("--dev", cmd)

    def test_environment_does_not_inherit_secrets(self):
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "secret", "SSH_AUTH_SOCK": "/socket",
                                          "HTTP_PROXY": "http://proxy", "PYTHONPATH": "/private"}):
            env = _minimal_env()
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        cmd = self.command()
        self.assertIn("--clearenv", cmd)
        self.assertNotIn("--setenv", cmd[-3:])

    def test_reject_relative_root(self):
        with self.assertRaises(ValueError):
            _workspace("relative")

    def test_reject_symlink_root(self):
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            _workspace(link)

    def test_reject_socket_symlink_and_fifo_inside_staging(self):
        link = self.root / "link"
        link.symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            _workspace(self.root)
        link.unlink()
        if hasattr(os, "mkfifo"):
            fifo = self.root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                _workspace(self.root)

    def test_reject_git_secrets_in_workspace(self):
        (self.root / ".git").mkdir()
        with self.assertRaises(ValueError):
            _workspace(self.root)

    def test_reject_hardlinked_workspace_file(self):
        original = self.root / "original"
        original.write_text("payload")
        os.link(original, self.root / "copy")
        with self.assertRaises(ValueError):
            _workspace(self.root)

    def test_reject_home_or_root_mount(self):
        with self.assertRaises(ValueError):
            _workspace("/")
        with self.assertRaises(ValueError):
            _workspace(str(Path.home()))

    def test_db_must_remain_outside_workspace(self):
        with self.assertRaises(ValueError):
            _state_path(self.root / "db.sqlite3", self.root)
        self.assertEqual(_state_path(Path(self.tmp.name) / "db.sqlite3", self.root),
                         Path(self.tmp.name) / "db.sqlite3")

    def test_db_relative_rejected(self):
        with self.assertRaises(ValueError):
            _state_path("relative.sqlite3", self.root)

    def test_agent_argv_must_be_absolute_sandbox_executable(self):
        for argv in ([], ["python3", "-c", "pass"], ["/home/me/script"], ["/usr/bin/python3", "a\x00b"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                build_command(self.root, argv, bwrap="/fake/bwrap")

    def test_exact_argv_preserved(self):
        argv = ["/usr/bin/python3", "-c", "print('hello world')", "with  spaces"]
        cmd = build_command(self.root, argv, bwrap="/fake/bwrap")
        self.assertEqual(cmd[-len(argv):], argv)

    def test_missing_bwrap_fails_closed(self):
        with patch("gateway.os_sandbox.shutil.which", return_value=None), \
             patch("gateway.os_sandbox.os.geteuid", return_value=1000):
            with self.assertRaises(SandboxUnavailable):
                _bwrap_binary()

    def test_root_launch_fails_closed(self):
        with patch("gateway.os_sandbox.os.geteuid", return_value=0):
            with self.assertRaises(SandboxUnavailable):
                _bwrap_binary()

    def test_transport_frame_is_forwarded_verbatim(self):
        source = io.BytesIO(b'{"jsonrpc":"2.0"}\n')
        target = io.BytesIO()
        # BytesIO can be read after close via getvalue only on some Python
        # versions; use a sink that captures data before close.
        class Sink(io.BytesIO):
            def close(self):
                self.saved = self.getvalue()
                super().close()
        sink = Sink()
        errors = []
        _pump(source, sink, errors)
        self.assertFalse(errors)
        self.assertEqual(sink.saved, b'{"jsonrpc":"2.0"}\n')

    def test_transport_rejects_unterminated_large_frame(self):
        class Sink(io.BytesIO):
            def close(self):
                pass
        errors = []
        _pump(io.BytesIO(b"x" * 131074), Sink(), errors)
        self.assertIn("ValueError", errors)

    def test_invalid_timeout_rejected_before_execution(self):
        with self.assertRaises(ValueError):
            run_child(self.root, ["/usr/bin/python3"], timeout=0)
        with self.assertRaises(ValueError):
            run_mcp_bridge(self.root, Path(self.tmp.name) / "db.sqlite3", ["/usr/bin/python3"], timeout=300)


if __name__ == "__main__":
    unittest.main()
