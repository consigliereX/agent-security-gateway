"""M5 regression: real OMP test harness is fail-closed and avoids host configuration."""
from __future__ import annotations
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib import request

from scripts.m5_real_omp import M5Unresolved, _copy_package_safe, stage_omp, EXPECTED_MARKER, _stage_installed_natives, _native_roots
from gateway.os_sandbox import build_command, _runtime_executable, _native_bundle
from scripts.m5_sandbox_controller import MockModel, STATE, ModelState


class M5StagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_standalone_elf_stage_is_readonly_copy(self):
        exe = self.base / 'real-omp'
        exe.write_bytes(b'\x7fELF' + b'compact test-only fixture')
        exe.chmod(0o755)
        stage = self.base / 'stage'
        stage.mkdir()
        with patch('scripts.m5_real_omp.shutil.which', return_value=str(exe)):
            outcome = stage_omp(stage)
        self.assertEqual(outcome['install'],'standalone_elf')
        self.assertEqual((stage/'omp-executable').read_bytes(),exe.read_bytes())

    def test_large_elf_separate_ro_bind_keeps_workspace_size_limit(self):
        exe = self.base / 'large-omp'
        exe.write_bytes(b'\x7fELF' + b'X' * 2048)
        exe.chmod(0o755)
        stage = self.base / 'stage'
        stage.mkdir()
        with patch('scripts.m5_real_omp.shutil.which', return_value=str(exe)), \
             patch('scripts.m5_real_omp.MAX_STAGED_BYTES', 512):
            outcome = stage_omp(stage, runtime_dir=self.base / 'private-runtime')
        private = Path(outcome['_runtime_file'])
        self.assertEqual(outcome['install'], 'standalone_elf_private_ro_bind')
        self.assertTrue(private.is_file())
        self.assertEqual(private.read_bytes(), exe.read_bytes())
        self.assertFalse((stage / 'omp-executable').exists())
        self.assertEqual(json.loads((stage / 'omp-launch.json').read_text()), ['/opt/asg-omp'])
        # Source binary is NOT included in the 256 MiB workspace budget.
        argv = build_command(stage, ['/usr/bin/python3','-c','pass'],
                             bwrap='/usr/bin/bwrap', runtime_executable=private)
        self.assertIn(['--ro-bind', str(private), '/opt/asg-omp'],
                      [argv[i:i+3] for i in range(len(argv)-2)])
        self.assertIn('--unshare-user', argv)
        self.assertIn('--unshare-net', argv) if '--unshare-net' in argv else self.assertIn('--unshare-all', argv)
        self.assertIn('--cap-drop', argv)

    def test_private_runtime_mount_rejects_symlink(self):
        stage = self.base / 'stage'
        stage.mkdir()
        private = self.base / 'private'
        private.mkdir(mode=0o700)
        valid = private / 'omp'
        valid.write_bytes(b'\x7fELF' + b'A' * 100)
        valid.chmod(0o500)
        link = self.base / 'link'
        link.symlink_to(valid)
        with self.assertRaises(ValueError):
            build_command(stage, ['/usr/bin/python3'], bwrap='/usr/bin/bwrap',
                          runtime_executable=link)

    def test_private_runtime_mount_rejects_group_access_and_non_elf(self):
        stage = self.base / 'stage'
        stage.mkdir()
        private = self.base / 'private'
        private.mkdir(mode=0o700)
        valid = private / 'omp'
        valid.write_bytes(b'bad content')
        valid.chmod(0o500)
        with self.assertRaisesRegex(ValueError, 'ELF'):
            _runtime_executable(valid, stage)
        # The prior 0o500 mode is intentionally non-writable. Restore owner
        # write permission for fixture setup, then remove it for validation.
        valid.chmod(0o700)
        valid.write_bytes(b'\x7fELF' + b'B' * 200)
        valid.chmod(0o555)
        with self.assertRaises(ValueError):
            _runtime_executable(valid, stage)

    def test_unrecognized_executable_denied(self):
        exe = self.base/'not-omp'
        exe.write_text('unrecognized binary')
        with patch('scripts.m5_real_omp.shutil.which',return_value=str(exe)):
            with self.assertRaises(M5Unresolved):
                stage_omp(self.base)

    def test_missing_omp_denied(self):
        with patch('scripts.m5_real_omp.shutil.which',return_value=None):
            with self.assertRaises(M5Unresolved):
                stage_omp(self.base)

    def test_copy_package_rejects_symlinks(self):
        src = self.base/'pkg'
        src.mkdir()
        (src/'link').symlink_to('/etc/passwd')
        with self.assertRaises(M5Unresolved):
            _copy_package_safe(src,self.base/'dest')

    def test_copy_package_rejects_hidden_secrets(self):
        src = self.base/'pkg'
        src.mkdir()
        (src/'agent.db').write_text('secret')
        with self.assertRaises(M5Unresolved):
            _copy_package_safe(src,self.base/'dest')

    def test_copy_package_rejects_hard_links(self):
        src = self.base/'pkg'
        src.mkdir()
        (src/'a').write_text('ok')
        os.link(src/'a', src/'b')
        with self.assertRaises(M5Unresolved):
            _copy_package_safe(src,self.base/'dest')


class M5NativeBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.stage = self.base / 'workspace'
        self.stage.mkdir(mode=0o700)
        self.cache = self.base / 'host-cache' / '18.13.3'
        self.cache.mkdir(mode=0o700, parents=True)
        self.dest = self.base / 'private-natives'

    def _make(self, name='pi_natives.linux-x64-baseline.node'):
        p = self.cache / name
        p.write_bytes(b'\x7fELF' + b'native-module-only-fixture')
        return p

    def test_exact_versioned_addon_is_copied_and_ro_mounted(self):
        src = self._make()
        outcome = _stage_installed_natives('18.13.3', self.dest, str(self.cache.parent))
        self.assertEqual([x['name'] for x in outcome['addons']], [src.name])
        self.assertEqual(outcome['addons'][0]['sha256'], __import__('hashlib').sha256(src.read_bytes()).hexdigest())
        copied = self.dest / '18.13.3' / src.name
        self.assertEqual(copied.read_bytes(), src.read_bytes())
        self.assertEqual(copied.stat().st_mode & 0o077, 0)
        command = build_command(self.stage, ['/usr/bin/python3','-c','pass'],
                                bwrap='/usr/bin/bwrap', native_bundle=self.dest)
        self.assertIn(['--ro-bind', str(self.dest), '/opt/asg-omp-natives'],
                      [command[i:i+3] for i in range(len(command)-2)])
        self.assertIn('--unshare-all', command)
        self.assertNotIn(str(self.cache), command)
        self.assertNotIn('--bind', command)

    def test_bad_version_rejected_without_access(self):
        self._make()
        for version in ('../../private', '18.13.3/../../x', '', 'invalid'):
            with self.subTest(version=version), self.assertRaises(M5Unresolved):
                _stage_installed_natives(version, self.dest, str(self.cache.parent))
        self.assertFalse(self.dest.exists())

    def test_missing_exact_version_fails_closed(self):
        self._make()
        with self.assertRaisesRegex(M5Unresolved, 'no matching local'):
            _stage_installed_natives('18.13.4', self.dest, str(self.cache.parent))
        self.assertFalse(self.dest.exists())

    def test_reject_symlinked_native_source(self):
        real = self.base / 'other'
        real.write_bytes(b'\x7fELF' + b'test')
        (self.cache / 'pi_natives.linux-x64-modern.node').symlink_to(real)
        with self.assertRaisesRegex(M5Unresolved, 'symlink'):
            _stage_installed_natives('18.13.3', self.dest, str(self.cache.parent))
        self.assertFalse(self.dest.exists())

    def test_source_hardlink_is_copied_to_independent_private_inode(self):
        source = self.base / 'outside-verified-elf'
        source.write_bytes(b'\x7fELF' + b'legit-local-cache-module')
        cached = self.cache / 'pi_natives.linux-x64.node'
        os.link(source, cached)
        self.assertEqual(cached.stat().st_nlink, 2)
        result = _stage_installed_natives('18.13.3', self.dest, str(self.cache.parent))
        copied = self.dest / '18.13.3' / cached.name
        self.assertEqual(copied.stat().st_nlink, 1)
        self.assertNotEqual(copied.stat().st_ino, cached.stat().st_ino)
        self.assertEqual(copied.read_bytes(), cached.read_bytes())
        self.assertEqual(result['addons'][0]['source_hardlinks'], 2)
        self.assertEqual(result['addons'][0]['private_copy_links'], 1)
        source.write_bytes(b'\x7fELF' + b'different-input')
        self.assertNotEqual(copied.read_bytes(), source.read_bytes())
        self.assertEqual(copied.stat().st_mode & 0o077, 0)
        argv = build_command(self.stage, ['/usr/bin/python3','-c','pass'],
                             bwrap='/usr/bin/bwrap', native_bundle=self.dest)
        self.assertIn(['--ro-bind', str(self.dest), '/opt/asg-omp-natives'],
                      [argv[i:i+3] for i in range(len(argv)-2)])

    def test_reject_non_elf_and_oversize(self):
        linked = self.cache / 'pi_natives.linux-x64.node'
        linked.write_bytes(b'NOT-ELF')
        with self.assertRaisesRegex(M5Unresolved, 'not an ELF'):
            _stage_installed_natives('18.13.3', self.dest, str(self.cache.parent))
        # Failed copy may create a partial private directory. The production
        # runner's temporary directory is always discarded on failed staging.
        from pathlib import Path
        if self.dest.exists():
            import shutil
            shutil.rmtree(self.dest)
        linked.write_bytes(b'\x7fELF' + b'B' * 60)
        import scripts.m5_real_omp as mod
        with patch.object(mod, 'MAX_NATIVE_BYTES', 32), self.assertRaisesRegex(M5Unresolved, 'bytes='):
            _stage_installed_natives('18.13.3', self.dest, str(self.cache.parent))

    def test_realistic_cached_addon_and_three_variant_budget(self):
        # Sparse ELF fixtures exercise size validation without allocating
        # hundreds of MiB of actual test data or opening a network connection.
        import scripts.m5_real_omp as runner
        self.assertEqual(runner.MAX_NATIVE_BYTES, 128 * 1024 * 1024)
        self.assertGreater(runner.MAX_NATIVE_BYTES, 117046824)
        self.dest.mkdir(mode=0o700)
        version = self.dest / '18.13.3'
        version.mkdir(mode=0o700)
        for name in runner.NATIVE_NAMES:
            path = version / name
            with path.open('wb') as f:
                f.write(b'\x7fELF')
                f.truncate(117046824)
            path.chmod(0o400)
        # Aggregate is >256 MiB, but private native bundle is not /work.
        self.assertGreater(3 * 117046824, 256 * 1024 * 1024)
        command = build_command(self.stage, ['/usr/bin/python3', '-c', 'pass'],
                                bwrap='/usr/bin/bwrap', native_bundle=self.dest)
        self.assertIn(['--ro-bind', str(self.dest), '/opt/asg-omp-natives'],
                      [command[i:i+3] for i in range(len(command)-2)])
        too_big = self.stage / 'over-workspace-cap.bin'
        with too_big.open('wb') as f:
            f.truncate(257 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, 'workspace'):
            build_command(self.stage, ['/usr/bin/python3', '-c', 'pass'],
                          bwrap='/usr/bin/bwrap', native_bundle=self.dest)

    def test_bundle_rejects_extra_entries_and_open_permissions(self):
        self._make()
        _stage_installed_natives('18.13.3', self.dest, str(self.cache.parent))
        (self.dest / '18.13.3' / 'auth.json').write_text('secret')
        with self.assertRaises(ValueError):
            _native_bundle(self.dest, self.stage)
        (self.dest / '18.13.3' / 'auth.json').unlink()
        self.dest.chmod(0o755)
        with self.assertRaises(ValueError):
            _native_bundle(self.dest, self.stage)

    def test_legacy_compiled_bin_cache_is_copied_not_mounted(self):
        legacy = self.base / '.local' / 'bin'
        legacy.mkdir(parents=True)
        native = legacy / 'pi_natives.linux-x64-modern.node'
        native.write_bytes(b'\x7fELF' + b'test-legacy-module')
        with patch('scripts.m5_real_omp.Path.home', return_value=self.base), \
             patch.dict(os.environ, {}, clear=True):
            result = _stage_installed_natives('18.13.3', self.dest)
        self.assertEqual(result['addons'][0]['name'], native.name)
        self.assertEqual((self.dest/'18.13.3'/native.name).read_bytes(),native.read_bytes())

    def test_fallback_discovery_includes_isolated_omp_home(self):
        with patch('scripts.m5_real_omp.Path.home', return_value=self.base), \
             patch.dict(os.environ, {}, clear=True):
            roots = _native_roots()
        self.assertIn(self.base / '.local/state/omp-local/home/.omp/natives', roots)

    def test_controller_pins_native_cache_path_without_host_env(self):
        import inspect
        import scripts.m5_sandbox_controller as c
        code = inspect.getsource(c.main)
        self.assertIn("'PI_NATIVES_DIR':'/opt/asg-omp-natives'", code)


class M5MockProviderTests(unittest.TestCase):
    def setUp(self):
        import scripts.m5_sandbox_controller as controller
        controller.STATE = ModelState()
        self.server = ThreadingHTTPServer(('127.0.0.1',0),MockModel)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 3)
        self.addCleanup(self.server.shutdown)

    def _request(self, offered, stream=False):
        body={'model':'probe','stream':stream,'tools':[{'type':'function','function':{'name':n}} for n in offered]}
        req=request.Request(f'http://127.0.0.1:{self.server.server_port}/v1/chat/completions',data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
        with request.urlopen(req,timeout=3) as resp:
            return resp.read().decode()

    def test_first_turn_attempts_host_bypass_through_real_tool(self):
        result=json.loads(self._request(['bash','mcp__asg_write_file']))
        self.assertEqual(result['choices'][0]['message']['tool_calls'][0]['function']['name'],'bash')
        arguments=json.loads(result['choices'][0]['message']['tool_calls'][0]['function']['arguments'])
        self.assertIn('/work/bypass-target.txt',arguments['command'])

    def test_second_turn_selects_only_gateway_mcp_tool(self):
        self._request(['bash','mcp__asg_write_file'])
        response=json.loads(self._request(['bash','mcp__asg_write_file']))
        call=response['choices'][0]['message']['tool_calls'][0]['function']
        self.assertEqual(call['name'],'mcp__asg_write_file')
        args=json.loads(call['arguments'])
        self.assertEqual(args['content'],EXPECTED_MARKER)

    def test_missing_mcp_tool_returns_no_fake_success(self):
        self._request(['bash'])
        response=json.loads(self._request(['bash']))
        self.assertIsNone(response['choices'][0]['message']['tool_calls'])

    def test_streaming_tool_call_contains_openai_compatible_events(self):
        result=self._request(['bash'],stream=True)
        self.assertIn('chat.completion.chunk',result)
        self.assertIn('"finish_reason":"tool_calls"',result)
        self.assertIn('data: [DONE]',result)

    def test_xdev_fallback_requests_real_device_listing(self):
        self._request(['bash', 'read', 'write'])
        response = json.loads(self._request(['bash', 'read', 'write']))
        call = response['choices'][0]['message']['tool_calls'][0]['function']
        self.assertEqual(call['name'], 'read')
        self.assertEqual(json.loads(call['arguments']), {'path': 'xd://'})

    def test_xdev_fallback_requires_device_name_from_result(self):
        self._request(['bash', 'read', 'write'])
        self._request(['bash', 'read', 'write'])
        body = {'model':'probe', 'tools':[{'type':'function', 'function':{'name':n}} for n in ['bash','read','write']],
                'messages':[{'role':'tool','content':'xd://mcp__asg_m5_asg_write_file'}]}
        req=request.Request(f'http://127.0.0.1:{self.server.server_port}/v1/chat/completions',
                            data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
        with request.urlopen(req, timeout=3) as resp:
            response=json.loads(resp.read())
        call = response['choices'][0]['message']['tool_calls'][0]['function']
        self.assertEqual(call['name'], 'write')
        args=json.loads(call['arguments'])
        self.assertEqual(args['path'], 'xd://mcp__asg_m5_asg_write_file')
        self.assertEqual(json.loads(args['content'])['content'], EXPECTED_MARKER)

    def test_final_turn_stops(self):
        self._request(['bash','mcp__asg_write_file'])
        self._request(['bash','mcp__asg_write_file'])
        last=json.loads(self._request(['bash','mcp__asg_write_file']))
        self.assertEqual(last['choices'][0]['finish_reason'],'stop')


class M5DiagnosticTests(unittest.TestCase):
    def test_child_stderr_capture_is_bounded_and_utf8_safe(self):
        import io
        from gateway.os_sandbox import _drain_child_stderr
        captured = []
        _drain_child_stderr(io.BytesIO(b"x" * 20000 + b"\nASG_M5_DIAG={}\n"), captured)
        self.assertEqual(len(captured), 1)
        self.assertLessEqual(len(captured[0]), 12288)
        self.assertTrue(captured[0].endswith(b"ASG_M5_DIAG={}\n"))

    def test_real_controller_emits_diagnostics_on_stderr_not_mcp_stdout(self):
        from pathlib import Path
        import inspect
        import scripts.m5_sandbox_controller as controller
        source = inspect.getsource(controller.main)
        self.assertIn("file=sys.stderr", source)
        self.assertIn("ASG_M5_DIAG=", source)
        self.assertIn("'omp_exit_zero'", source)
        self.assertIn("'mediated_route_offered'", source)



class M5StartupDeadlineTests(unittest.TestCase):
    def test_timeout_capture_keeps_stdout_and_stderr(self):
        from importlib.util import module_from_spec, spec_from_file_location
        import subprocess
        module_path = Path(__file__).resolve().parents[1] / 'scripts' / 'm5_sandbox_controller.py'
        spec = spec_from_file_location('asg_m5_controller_timeout', module_path)
        ctrl = module_from_spec(spec)
        spec.loader.exec_module(ctrl)
        self.assertEqual(ctrl._decode_capture(b'before\n'), 'before\n')
        self.assertEqual(ctrl._decode_capture(None), '')
        self.assertEqual(ctrl._decode_capture(b'bad\xffbyte'), 'bad\ufffdbyte')
        self.assertEqual(len(ctrl._decode_capture(b'Z' * 9000)), 8192)

    def test_timeout_and_mcp_accept_deadlines_not_equal(self):
        from pathlib import Path
        source = (Path(__file__).resolve().parents[1] / 'scripts' / 'm5_sandbox_controller.py').read_text()
        self.assertIn('listener.settimeout(85)', source)
        self.assertIn('timeout=70', source)
        self.assertIn("'omp_timed_out':agent_timed_out", source)
        self.assertIn('mcp_connected.set()', source)
        self.assertIn("'relay_clean': not errors and mcp_connected.is_set()", source)

    def test_timeout_expired_partial_bytes_preserved_in_diagnostic(self):
        import subprocess
        try:
            subprocess.run(['/usr/bin/python3','-c',
                            'import sys,time;sys.stderr.write("START\\n");sys.stderr.flush();time.sleep(1)'],
                           capture_output=True, text=True, timeout=0.2)
        except subprocess.TimeoutExpired as exc:
            from importlib.util import module_from_spec, spec_from_file_location
            module_path = Path(__file__).resolve().parents[1] / 'scripts' / 'm5_sandbox_controller.py'
            spec = spec_from_file_location('asg_m5_controller_capture', module_path)
            ctrl = module_from_spec(spec)
            spec.loader.exec_module(ctrl)
            self.assertIn('START', ctrl._decode_capture(exc.stderr))
        else:
            self.fail('timeout fixture did not time out')


class M5StdinIsolationTests(unittest.TestCase):
    def test_headless_omp_receives_eof_without_consuming_mcp_pipe(self):
        """An OMP-like stdin reader must finish even while MCP stdin stays open."""
        import subprocess
        import sys
        from scripts.m5_sandbox_controller import run_headless_omp
        with tempfile.TemporaryDirectory() as td:
            command = [sys.executable, '-c',
                       'import sys; assert sys.stdin.read() == ""; print("STDIN_EOF")']
            # Keep the parent's stdin unrelated to the prompt process; the
            # controller's separate MCP stdin is intentionally not consumed.
            result = run_headless_omp(command, dict(os.environ), cwd=td, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'STDIN_EOF')

    def test_controller_uses_headless_stdin_isolation(self):
        import inspect
        from scripts import m5_sandbox_controller as controller
        source = inspect.getsource(controller.main)
        self.assertIn("run_headless_omp(command, env, cwd='/work', timeout=70)", source)
        helper = inspect.getsource(controller.run_headless_omp)
        self.assertIn('stdin=subprocess.DEVNULL', helper)


if __name__ == '__main__':
    unittest.main()
