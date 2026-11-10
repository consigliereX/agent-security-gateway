#!/usr/bin/env python3
"""M5: real OMP agent boundary check inside Bubblewrap with a trusted M4 MCP broker.

Deliberately uses a deterministic in-namespace OpenAI-compatible model stub.
No host model credentials or inference services are used. M5 is an actual OMP
binary + MCP client validation, NOT a test of model reasoning or Claude Code.
Only an explicitly selected OMP executable is staged, with size/type checks.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import os
import shutil
import subprocess
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from gateway.os_sandbox import SandboxUnavailable, _bwrap_binary, run_child, run_mcp_bridge, _verify_staged_tree

EXPECTED_MARKER = 'ASG_M5_AGENT_ONLY'
MAX_STAGED_FILES = 8500
MAX_STAGED_BYTES = 235 * 1024 * 1024
MAX_PRIVATE_RUNTIME_BYTES = 1024 * 1024 * 1024  # separate, single-ELF cap; workspace limit remains unchanged


class M5Unresolved(RuntimeError):
    """The installed OMP binary or its tool protocol could not be verified."""


def _copy_file(src: Path, dest: Path) -> None:
    meta = src.stat()
    if not src.is_file() or not stat.S_ISREG(meta.st_mode):
        raise M5Unresolved('OMP source is not a regular file')
    if meta.st_size > MAX_STAGED_BYTES:
        raise M5Unresolved('OMP binary is too large for safe staging')
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    dest.chmod(0o700 if meta.st_mode & 0o111 else 0o600)


def _copy_package_safe(src: Path, dest: Path) -> None:
    count = 0
    total = 0
    for parent, dirs, files in os.walk(src, followlinks=False):
        p = Path(parent)
        rel = p.relative_to(src)
        where = dest / rel
        where.mkdir(parents=True, exist_ok=True)
        for name in [*dirs, *files]:
            child = p / name
            st = child.lstat()
            count += 1
            if count > MAX_STAGED_FILES:
                raise M5Unresolved('OMP runtime package exceeds staged file cap')
            if name in {'.git', '.venv', '.env', 'auth.json', 'agent.db'}:
                raise M5Unresolved('unexpected sensitive/runtime file in OMP package')
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise M5Unresolved('OMP package contains symlink/non-regular file; not copying it')
            if st.st_nlink != 1 and stat.S_ISREG(st.st_mode):
                raise M5Unresolved('OMP package contains a hard link')
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
                if total > MAX_STAGED_BYTES:
                    raise M5Unresolved('OMP package exceeds maximum staged size')
                _copy_file(child, where / name)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for piece in iter(lambda: source.read(1024*1024), b''):
            digest.update(piece)
    return digest.hexdigest()


def _stage_private_runtime(source: Path, private_dir: Path) -> Path:
    """Copy a large ELF into a disposable, owner-only directory OUTSIDE /work."""
    st = source.stat()
    if (not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_PRIVATE_RUNTIME_BYTES
        or source.is_symlink()):
        raise M5Unresolved('OMP runtime is not a safe regular ELF within the 1 GiB cap')
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    target = private_dir / 'omp'
    with source.open('rb') as inp, target.open('xb') as out:
        shutil.copyfileobj(inp, out, length=1024 * 1024)
    target.chmod(0o500)
    if _sha256_file(target) != _sha256_file(source):
        raise M5Unresolved('private runtime integrity verification failed')
    return target


def stage_omp(root: Path, runtime_dir: Path | None = None) -> dict:
    binary = shutil.which('omp')
    if not binary:
        raise M5Unresolved('omp executable not found in PATH')
    source = Path(binary).resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise M5Unresolved('OMP launcher must resolve to a regular file')
    with source.open('rb') as fp:
        header = fp.read(96)
    if header.startswith(b'\x7fELF'):
        if source.stat().st_size > MAX_STAGED_BYTES:
            if runtime_dir is None:
                raise M5Unresolved('large OMP ELF requires a separate private runtime directory')
            private = _stage_private_runtime(source, runtime_dir)
            (root / 'omp-launch.json').write_text(json.dumps(['/opt/asg-omp']))
            return {'install':'standalone_elf_private_ro_bind',
                    '_runtime_file':str(private),'source_sha256':_sha256_file(source),
                    'source_bytes':source.stat().st_size}
        _copy_file(source, root / 'omp-executable')
        return {'install':'standalone_elf', 'source_sha256':_sha256_file(source),
                'source_bytes':source.stat().st_size}
    if not header.startswith(b'#!'):
        raise M5Unresolved('OMP is neither ELF nor supported script install')
    # Resolve the package root rather than copying the user's home/profile.
    package_root = None
    for parent in source.parents:
        if parent.name == 'pi-coding-agent' and (parent / 'package.json').is_file():
            package_root = parent
            break
    if package_root is None:
        raise M5Unresolved('OMP script package layout not recognized; no ambient directories copied')
    if len(package_root.parts) < 5:
        raise M5Unresolved('unsafe OMP package root')
    runtime = shutil.which('bun')
    if not runtime:
        runtime = shutil.which('node')
    if not runtime:
        raise M5Unresolved('OMP script requires bun/node; no runtime found')
    runtime_path = Path(runtime).resolve(strict=True)
    with runtime_path.open('rb') as fp:
        runtime_magic = fp.read(4)
    if runtime_magic != b'\x7fELF':
        raise M5Unresolved('Bun/Node runtime is not a standalone ELF')
    runtime_entry = '/work/omp-runtime'
    external_runtime = None
    if runtime_path.stat().st_size > MAX_STAGED_BYTES:
        if runtime_dir is None:
            raise M5Unresolved('large Bun/Node ELF requires private runtime staging')
        external_runtime = _stage_private_runtime(runtime_path, runtime_dir)
        runtime_entry = '/opt/asg-omp'
    else:
        _copy_file(runtime_path, root / 'omp-runtime')
    _copy_package_safe(package_root, root / 'omp-package')
    relative_entry = source.relative_to(package_root)
    (root / 'omp-launch.json').write_text(json.dumps([runtime_entry, '/work/omp-package/' + relative_entry.as_posix()]))
    out = {'install':'script_bun_node', 'source_sha256':_sha256_file(source),
           'source_bytes':source.stat().st_size}
    if external_runtime:
        out['_runtime_file'] = str(external_runtime)
    return out




NATIVE_NAMES = (
    'pi_natives.linux-x64-modern.node',
    'pi_natives.linux-x64-baseline.node',
    'pi_natives.linux-x64.node',
)
MAX_NATIVE_BYTES = 128 * 1024 * 1024


def _native_roots(override: str = '') -> list[Path]:
    """Use only narrow installed native-cache locations, never scan home recursively."""
    home = Path.home()
    candidates = []
    if override:
        candidates.append(Path(override).expanduser())
    else:
        explicit = os.environ.get('PI_NATIVES_DIR', '')
        if explicit:
            candidates.append(Path(explicit).expanduser())
        xdg = os.environ.get('XDG_DATA_HOME', '')
        if xdg:
            candidates.append(Path(xdg).expanduser() / 'omp' / 'natives')
        candidates += [
            home / '.omp' / 'natives',
            home / '.local' / 'share' / 'omp' / 'natives',
            home / '.local' / 'state' / 'omp-local' / 'home' / '.omp' / 'natives',
            home / '.local' / 'state' / 'omp-local' / 'home' / '.local' / 'share' / 'omp' / 'natives',
            # Compiled OMP's legacy unversioned native-addon fallback.
            home / '.local' / 'bin',
            home / '.local' / 'state' / 'omp-local' / 'home' / '.local' / 'bin',
        ]
    return list(dict.fromkeys(candidates))


def _copy_verified_native(source: Path, target: Path) -> dict:
    """Copy a cached ELF into a new private inode; never bind its original inode.

    A host cache can legitimately be hardlinked (e.g. package-manager dedupe).
    Source link count is not a confinement property once bytes are copied.
    Reject links that are *symlinks*, nonregular sources and unsupported sizes.
    """
    if source.is_symlink():
        raise M5Unresolved('cached native addon is a symlink: ' + source.name)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    try:
        handle = os.open(source, flags)
    except OSError as exc:
        raise M5Unresolved('cannot safely open native addon: ' + source.name +
                           ' (' + type(exc).__name__ + ')') from exc
    with os.fdopen(handle, 'rb') as inp:
        before = os.fstat(inp.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink < 1:
            raise M5Unresolved('cached native addon is not a regular linked file: ' + source.name)
        if not 0 < before.st_size <= MAX_NATIVE_BYTES:
            raise M5Unresolved(f'cached native addon size rejected: {source.name} '
                               f'bytes={before.st_size} cap={MAX_NATIVE_BYTES}')
        if inp.read(4) != b'\x7fELF':
            raise M5Unresolved('cached native addon is not an ELF: ' + source.name)
        inp.seek(0)
        digest = hashlib.sha256()
        written = 0
        with target.open('xb') as out:
            while True:
                chunk = inp.read(min(1024 * 1024, MAX_NATIVE_BYTES + 1 - written))
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_NATIVE_BYTES:
                    raise M5Unresolved('native addon changed beyond size cap during staging')
                digest.update(chunk)
                out.write(chunk)
        after = os.fstat(inp.fileno())
        old_identity = (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
        new_identity = (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)
        if old_identity != new_identity or written != before.st_size:
            raise M5Unresolved('native addon changed while being staged: ' + source.name)
        try:
            path_stat = source.lstat()
        except OSError as exc:
            raise M5Unresolved('native addon source disappeared during copy') from exc
        if (path_stat.st_dev, path_stat.st_ino) != (before.st_dev, before.st_ino):
            raise M5Unresolved('native addon source path replaced during copy')
    target.chmod(0o400)
    installed = target.lstat()
    if (not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1
        or installed.st_uid != os.getuid() or (installed.st_mode & 0o077)
        or installed.st_size != written or _sha256_file(target) != digest.hexdigest()):
        raise M5Unresolved('private native addon copy integrity failed: ' + source.name)
    return {'name':source.name, 'sha256':digest.hexdigest(), 'bytes':written,
            'source_hardlinks':before.st_nlink, 'private_copy_links':installed.st_nlink}


def _stage_installed_natives(version: str, destination: Path,
                             override: str = '') -> dict:
    """Stage matching local native ELF addons, read-only and with new private inodes."""
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', version):
        raise M5Unresolved('cannot safely parse exact OMP native addon version')
    for root in _native_roots(override):
        legacy_bin = root.name == 'bin' and root.parent.name == '.local'
        version_path = root if root.name == version or legacy_bin else root / version
        if not version_path.is_dir() or version_path.is_symlink():
            continue
        matched = []
        for name in NATIVE_NAMES:
            path = version_path / name
            if path.is_symlink():
                raise M5Unresolved('native addon cache contains a symlink: ' + name)
            if path.exists():
                matched.append(path)
        if not matched:
            continue
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        version_dir = destination / version
        version_dir.mkdir(mode=0o700)
        evidence = []
        for source in matched:
            evidence.append(_copy_verified_native(source, version_dir / source.name))
        return {'_native_bundle':str(destination), 'version':version, 'addons':evidence}
    raise M5Unresolved('no matching local pi_natives addon cache for '+version+
                       '; run OMP outside the sandbox once or use --native-dir')


def run(repo: Path, evidence: Path, native_dir: str = "") -> dict:
    repo = repo.resolve(strict=True)
    report = {'when':datetime.now(timezone.utc).isoformat(),
              'mode':'real_omp_in_bubblewrap__deterministic_in_namespace_model',
              'host_secrets_provided':False,'host_inference_access':False,
              'config_modified':False, 'actual_claude_code_tested':False,
              'result':'UNRESOLVED'}
    try:
        _bwrap_binary()  # mandatory security preflight; records failure evidence
        with tempfile.TemporaryDirectory(prefix='asg-m5-',dir=None) as td:
            base = Path(td)
            root = base / 'staged-work'
            root.mkdir(mode=0o700)
            for name in ['m5_sandbox_controller.py', 'm5_mcp_relay.py']:
                _copy_file(repo/'scripts'/name, root/name)
            (root / 'bypass-target.txt').write_text('ORIGINAL')
            staged = stage_omp(root, runtime_dir=base / 'private-runtime')
            runtime_file = staged.pop('_runtime_file', None)
            report['omp'] = staged
            _verify_staged_tree(root)
            # Prove the installed OMP executable itself starts INSIDE the sandbox.
            # stdout/stderr are bounded diagnostic excerpts, never user config.
            version_code = ("import json,subprocess,pathlib; "
                            "m=pathlib.Path('/work/omp-launch.json'); "
                            "argv=json.loads(m.read_text()) if m.exists() else ['/work/omp-executable']; "
                            "r=subprocess.run(argv+['--version'],capture_output=True,text=True,timeout=8); "
                            "print((r.stdout or r.stderr)[:300]); raise SystemExit(r.returncode)")
            preflight = run_child(root, ['/usr/bin/python3','-c',version_code],
                                  timeout=15, runtime_executable=runtime_file)
            report['omp_sandbox_version_rc'] = preflight.returncode
            report['omp_version'] = preflight.stdout.strip()[:160]
            report['omp_preflight_error'] = preflight.stderr.strip()[:500]
            if preflight.returncode != 0:
                raise M5Unresolved('OMP did not start inside the sandbox; inspect preflight error')
            match = re.search(r'\b[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\b',
                              report['omp_version'])
            if not match:
                raise M5Unresolved('OMP --version has no parseable package version')
            native = _stage_installed_natives(match.group(), base / 'private-natives', native_dir)
            native_bundle = native.pop('_native_bundle')
            report['native_addons'] = native
            db = base / 'trusted-gateway.sqlite3'
            diagnostics = {}
            child_rc, broker_rc = run_mcp_bridge(
                root, db, ['/usr/bin/python3','/work/m5_sandbox_controller.py'],
                timeout=115, repo_root=repo, runtime_executable=runtime_file,
                native_bundle=native_bundle, diagnostics=diagnostics)
            raw = diagnostics.get('child_stderr_tail', '')
            report['controller_stderr_tail'] = raw[-4096:]
            for line in reversed(raw.splitlines()):
                if line.startswith('ASG_M5_DIAG='):
                    try:
                        diag = json.loads(line[len('ASG_M5_DIAG='):])
                    except (ValueError, TypeError):
                        report['controller_diagnostic_parse_error'] = True
                    else:
                        if isinstance(diag, dict):
                            report['omp_diagnostics'] = diag
                    break
            report['child_rc'] = child_rc
            report['broker_rc'] = broker_rc
            direct = (root/'bypass-target.txt').read_text() == 'ORIGINAL'
            mediated = root/'m5-mediated.txt'
            mediated_good = mediated.is_file() and mediated.read_text() == EXPECTED_MARKER
            report['direct_write_blocked'] = direct
            report['mediated_write_verified'] = mediated_good
            if db.exists():
                with sqlite3.connect(db) as conn:
                    rows = conn.execute("SELECT action_type, action_target, decision FROM audit_events ORDER BY event_id").fetchall()
                report['audit_event_count'] = len(rows)
                report['mediated_audit_event_present'] = any(
                    kind == 'write_filesystem' and 'm5-mediated.txt' in target and decision in {'allow','allow_with_redaction'}
                    for kind,target,decision in rows)
            else:
                report['audit_event_count'] = 0
                report['mediated_audit_event_present'] = False
            if (child_rc != 0 or broker_rc != 0 or not direct or not mediated_good or
                not report['mediated_audit_event_present']):
                raise M5Unresolved('real OMP/MCP sandbox acceptance failed (see result fields)')
            report['result'] = 'PASS_REAL_OMP_SANDBOXED_MCP_MEDIATION'
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
        report['unresolved_reason'] = type(exc).__name__ + ': ' + str(exc)[:250]
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', type=Path, default=Path.cwd())
    ap.add_argument('--native-dir', default='', help='optional exact installed native cache root (read-only source)')
    ap.add_argument('--evidence', type=Path,required=True)
    opt = ap.parse_args()
    report = run(opt.repo,opt.evidence,opt.native_dir)
    if report['result'].startswith('PASS'):
        print('PASS: actual OMP process isolated by Bubblewrap; MCP write authorized by host gateway')
        print('PASS: direct workspace bypass denied; host files and model remain unexposed')
        print('EVIDENCE: ' + str(opt.evidence))
        return 0
    print('UNRESOLVED: '+report.get('unresolved_reason','M5 acceptance incomplete'),file=sys.stderr)
    diag = report.get('omp_diagnostics', {})
    if isinstance(diag, dict) and diag:
        facts = {'omp_rc': diag.get('omp_returncode'),
                 'omp_timed_out': diag.get('omp_timed_out'),
                 'mcp_client_connected': diag.get('mcp_client_connected'),
                 'model_requests': diag.get('model_requests'),
                 'scripted_tools': [x.get('tool') for x in diag.get('scripted_tool_calls', []) if isinstance(x, dict)],
                 'checks': diag.get('checks'),
                 'relay_errors': diag.get('relay_errors'),
                 'model_errors': diag.get('model_errors')}
        print('FIND: OMP diagnostic '+json.dumps(facts, separators=(',',':')), file=sys.stderr)
        for key in ('agent_stderr_tail', 'agent_stdout_tail'):
            snippet = str(diag.get(key, '')).strip()[-600:]
            if snippet:
                print('FIND: '+key+'='+repr(snippet), file=sys.stderr)
    elif report.get('controller_stderr_tail'):
        print('FIND: controller stderr tail '+repr(report['controller_stderr_tail'][-450:]), file=sys.stderr)
    print('EVIDENCE: '+str(opt.evidence),file=sys.stderr)
    return 2


if __name__=='__main__':
    raise SystemExit(main())
