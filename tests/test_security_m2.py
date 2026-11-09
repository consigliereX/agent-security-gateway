"""M2 regression tests: deny redirects and close filesystem symlink races."""
from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib import request as urllib_request

from firewall.adapters import AdapterContext, FileSystemAdapter, HttpAdapter, _NoRedirect


class AllowService:
    def __init__(self, before=None):
        self.calls = []
        self.before = before

    def inspect(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == 1 and self.before is not None:
            self.before()
        return {"decision": "allow"}


class M2HttpTests(unittest.TestCase):
    def setUp(self):
        self.ctx = AdapterContext(session_id="s", user_input="test")

    def test_non_http_and_credentials_denied_before_inspect(self):
        svc = AllowService()
        adapter = HttpAdapter(service=svc, allowed_hosts=["localhost"])
        for url in ("file:///etc/passwd", "ftp://localhost/file", "http://user:pass@localhost/a",
                    "http://localhost:invalid/a", "http://localhost\n/a", "http://evil.invalid/a"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                adapter.request("GET", url, self.ctx)
        self.assertEqual(svc.calls, [])

    def test_redirect_handler_denies_destination_change(self):
        with self.assertRaisesRegex(ValueError, "redirect denied"):
            _NoRedirect().redirect_request(None, None, 302, "Found", {"Location": "http://evil.invalid/"}, "http://evil.invalid/")

    def test_http_uses_egress_safe_opener(self):
        svc = AllowService()
        adapter = HttpAdapter(service=svc, allowed_hosts=["localhost"])
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self): return b"ok"
        with patch("firewall.adapters.url_request.build_opener") as build:
            build.return_value.open.return_value = Response()
            self.assertEqual(adapter.request("GET", "http://localhost/test", self.ctx), "ok")
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(x, _NoRedirect) for x in handlers))
        self.assertTrue(any(isinstance(x, urllib_request.ProxyHandler) and x.proxies == {} for x in handlers))
        self.assertEqual(len(svc.calls), 2)

    def test_live_loopback_redirect_target_never_contacted(self):
        # Localhost-only integration test; no external network connections.
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/finish")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"reached")
            def log_message(self, *_):
                pass
        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                adapter = HttpAdapter(service=AllowService(), allowed_hosts=["127.0.0.1"])
                with self.assertRaisesRegex(ValueError, "redirect denied"):
                    adapter.request("GET", f"http://127.0.0.1:{server.server_port}/start", self.ctx)
                self.assertEqual(hits, ["/start"])
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_3xx_is_denied_even_if_response_is_returned(self):
        svc = AllowService()
        adapter = HttpAdapter(service=svc, allowed_hosts=["localhost"])
        class Response:
            status = 302
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self): return b"redirect"
        with patch("firewall.adapters.url_request.build_opener") as build:
            build.return_value.open.return_value = Response()
            with self.assertRaisesRegex(ValueError, "redirect denied"):
                adapter.request("GET", "http://localhost/test", self.ctx)
        self.assertEqual(len(svc.calls), 1)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd, "POSIX dirfd required")
class M2FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "base"
        self.base.mkdir()
        self.external = Path(self.tmp.name) / "outside"
        self.external.mkdir()
        self.ctx = AdapterContext(session_id="s", user_input="test")

    def test_nested_read_write_and_utf8_byte_limit(self):
        svc = AllowService()
        adapter = FileSystemAdapter(service=svc, base_dir=str(self.base), max_bytes=5)
        adapter.write_text("sub/file.txt", "😀😀", self.ctx)
        self.assertEqual((self.base / "sub/file.txt").read_text(), "😀")
        self.assertEqual(adapter.read_text("sub/file.txt", self.ctx), "😀")
        self.assertEqual(len(svc.calls), 4)

    def test_lexical_escape_denied(self):
        adapter = FileSystemAdapter(service=AllowService(), base_dir=str(self.base))
        for path in ("../outside/file", "/etc/passwd", ".", ""):
            with self.subTest(path=path), self.assertRaises(ValueError):
                adapter.read_text(path, self.ctx)

    def test_parent_symlink_denied(self):
        (self.base / "link").symlink_to(self.external, target_is_directory=True)
        adapter = FileSystemAdapter(service=AllowService(), base_dir=str(self.base))
        with self.assertRaises((OSError, ValueError)):
            adapter.write_text("link/escape", "secret", self.ctx)
        self.assertFalse((self.external / "escape").exists())

    def test_final_symlink_denied(self):
        victim = self.external / "victim"
        victim.write_text("original")
        (self.base / "link").symlink_to(victim)
        adapter = FileSystemAdapter(service=AllowService(), base_dir=str(self.base))
        with self.assertRaises((OSError, ValueError)):
            adapter.write_text("link", "bad", self.ctx)
        self.assertEqual(victim.read_text(), "original")
        with self.assertRaises((OSError, ValueError)):
            adapter.read_text("link", self.ctx)

    def test_symlink_swap_during_policy_inspection_denied(self):
        victim = self.external / "victim"
        victim.write_text("original")
        target = self.base / "safe.txt"
        target.write_text("local")
        def swap():
            target.unlink()
            target.symlink_to(victim)
        adapter = FileSystemAdapter(service=AllowService(before=swap), base_dir=str(self.base))
        with self.assertRaises((OSError, ValueError)):
            adapter.write_text("safe.txt", "bad", self.ctx)
        self.assertEqual(victim.read_text(), "original")

    def test_root_replacement_denied(self):
        adapter = FileSystemAdapter(service=AllowService(), base_dir=str(self.base))
        self.base.rename(self.base.with_name("old-base"))
        self.base.mkdir()
        with self.assertRaises((OSError, ValueError)):
            adapter.write_text("foo", "bad", self.ctx)
        self.assertFalse((self.base / "foo").exists())

    def test_hardlinked_writes_denied(self):
        victim = self.external / "victim"
        victim.write_text("original")
        os.link(victim, self.base / "linked")
        adapter = FileSystemAdapter(service=AllowService(), base_dir=str(self.base))
        with self.assertRaises(ValueError):
            adapter.write_text("linked", "bad", self.ctx)
        self.assertEqual(victim.read_text(), "original")

    def test_fifo_denied_without_block(self):
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        adapter = FileSystemAdapter(service=AllowService(), base_dir=str(self.base))
        with self.assertRaises(ValueError):
            adapter.read_text("fifo", self.ctx)


if __name__ == "__main__":
    unittest.main()
