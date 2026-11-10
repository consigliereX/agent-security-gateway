"""M4: fail-closed Linux namespace launcher for explicitly selected agent children.

The trusted MCP gateway process runs OUTSIDE the sandbox. The untrusted agent
child runs in an unprivileged bubblewrap namespace with only a read-only
workspace, disposable /tmp, no host home, and no network. Stdout/stdin are
reserved for JSON-line MCP communication; the agent has no host shell rights.

This is an OS process boundary for the CHILD ONLY, not automatic isolation of
an existing OMP/Claude Code process or an LLM server running on the host.
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import IO, Sequence


class SandboxUnavailable(RuntimeError):
    """A required sandbox security property cannot be established."""


def _workspace(root: str | Path) -> Path:
    path = Path(root).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing absolute, non-symlink directory")
    resolved = path.resolve(strict=True)
    if resolved == Path("/") or resolved == Path.home().resolve():
        raise ValueError("refusing to expose filesystem root or home as workspace")
    _verify_staged_tree(resolved)
    return resolved


def _verify_staged_tree(root: Path, *, max_total_bytes: int = 256 * 1024 * 1024) -> None:
    """Refuse nonregular objects and nested mounts that expose host resources."""
    # Explicitly reject bind-mounted subdirectories, including same-device
    # bind mounts that a simple st_dev comparison would not identify.
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError as exc:
        raise SandboxUnavailable("cannot inspect host mount namespace") from exc
    for line in lines:
        fields = line.split(" - ", 1)[0].split()
        if len(fields) < 5:
            raise SandboxUnavailable("malformed mountinfo")
        mount_path = fields[4]
        for octal, character in (("\\040", " "), ("\\011", "\t"),
                                 ("\\012", "\n"), ("\\134", "\\")):
            mount_path = mount_path.replace(octal, character)
        point = Path(mount_path)
        if point != root and root in point.parents:
            raise ValueError("workspace includes a nested mount point")

    root_dev = root.stat().st_dev
    pending = [root]
    count = 0
    total_size = 0
    while pending:
        folder = pending.pop()
        with os.scandir(folder) as entries:
            for entry in entries:
                count += 1
                if count > 10000:
                    raise ValueError("workspace has too many entries; stage a smaller directory")
                if entry.name in {".git", ".venv", ".env"}:
                    raise ValueError("workspace contains repository metadata, venv or env secrets")
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != root_dev:
                    raise ValueError("workspace crosses a filesystem boundary")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1:
                        raise ValueError("workspace contains a hard-linked file")
                    total_size += info.st_size
                    if total_size > max_total_bytes:
                        raise ValueError("workspace exceeds 256 MiB staged file limit")
                else:
                    raise ValueError("workspace contains a symlink, socket, device or FIFO")


def _state_path(raw: str | Path, root: Path) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("state database must be an absolute, non-symlink path")
    # Path may not exist yet; resolve verifies all existing parents.
    path = path.resolve()
    if path == root or root in path.parents:
        raise ValueError("state database must be outside the agent workspace")
    if path.is_dir():
        raise ValueError("state database cannot be a directory")
    return path


def _bwrap_binary() -> str:
    if sys.platform != "linux" or os.name != "posix":
        raise SandboxUnavailable("Linux and unprivileged bubblewrap are required")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SandboxUnavailable("run this sandbox launcher as an unprivileged user, not root")
    binary = shutil.which("bwrap")
    if not binary:
        raise SandboxUnavailable("bubblewrap is missing (Arch: sudo pacman -S bubblewrap)")
    trusted = Path("/usr/bin/bwrap")
    path = Path(binary).resolve()
    if path != trusted or not trusted.is_file() or trusted.is_symlink():
        raise SandboxUnavailable("only the system /usr/bin/bwrap binary is accepted")
    metadata = trusted.stat()
    if metadata.st_uid != 0 or (metadata.st_mode & 0o022):
        raise SandboxUnavailable("bubblewrap binary must be root-owned and not group/world writable")
    return str(trusted)


def _minimal_env() -> dict[str, str]:
    # Never propagate HOME, cloud tokens, SSH agent, proxy settings, display,
    # agent tool settings, or untrusted PYTHONPATH into a sandboxed child.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def _runtime_executable(path: str | Path, root: Path) -> Path:
    """Accept one deliberately staged, private ELF executable as a read-only mount.

    This is NOT a facility to bind arbitrary host directories. The one mounted
    file must be owned by the current user, private, non-linked, within a
    private owned staging directory, and outside the exposed workspace.
    """
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ValueError("runtime executable must be an absolute, non-symlink file")
    candidate = candidate.resolve(strict=True)
    if candidate == root or root in candidate.parents:
        raise ValueError("runtime executable must be outside the workspace")
    st = candidate.stat()
    parent = candidate.parent
    pst = parent.stat()
    if (not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 1024 * 1024 * 1024
        or st.st_nlink != 1 or st.st_uid != os.getuid()
        or (st.st_mode & 0o077) != 0 or not (st.st_mode & stat.S_IXUSR)
        or not stat.S_ISDIR(pst.st_mode) or pst.st_uid != os.getuid()
        or (pst.st_mode & 0o077) != 0 or parent.is_symlink()):
        raise ValueError("runtime must be a private owner-only executable in a private directory")
    with candidate.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("only a staged ELF binary can be mounted")
    return candidate


def _native_bundle(path: str | Path, root: Path) -> Path:
    """Validate one disposable version-scoped addon directory; never bind user home.

    The native executable code is copied from a local installation to an
    owner-only directory; its host source and other user data stay invisible.
    """
    raw = Path(path).expanduser()
    if not raw.is_absolute() or raw.is_symlink() or not raw.is_dir():
        raise ValueError("native bundle must be an existing absolute non-symlink directory")
    bundle = raw.resolve(strict=True)
    if bundle == root or root in bundle.parents or bundle in root.parents:
        raise ValueError("native bundle must not contain/overlap workspace")
    for folder in (bundle, bundle.parent):
        st = folder.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or (st.st_mode & 0o077) or folder.is_symlink()):
            raise ValueError("native bundle directory must be private and owner-only")
    versions = list(bundle.iterdir())
    if len(versions) != 1 or not versions[0].is_dir() or versions[0].is_symlink():
        raise ValueError("native bundle must hold exactly one version directory")
    if not __import__('re').fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", versions[0].name):
        raise ValueError("invalid native bundle version")
    st = versions[0].lstat()
    if st.st_uid != os.getuid() or (st.st_mode & 0o077):
        raise ValueError("native version directory must be private")
    entries = list(versions[0].iterdir())
    names = {"pi_natives.linux-x64-modern.node", "pi_natives.linux-x64-baseline.node",
             "pi_natives.linux-x64.node"}
    if not 1 <= len(entries) <= len(names):
        raise ValueError("native bundle requires 1..3 approved addon files")
    for file in entries:
        st = file.lstat()
        if file.name not in names or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ValueError("native bundle contains an unexpected or linked item")
        if st.st_uid != os.getuid() or (st.st_mode & 0o077) or not (0 < st.st_size <= 128 * 1024 * 1024):
            raise ValueError("native addon must be private, nonempty and at most 128 MiB")
        with file.open('rb') as stream:
            if stream.read(4) != b"\x7fELF":
                raise ValueError("native addon must be an ELF shared library")
    # Native addons live outside the agent workspace. Up to three approved
    # variants may each be 128 MiB; the /work cap remains 256 MiB.
    _verify_staged_tree(bundle, max_total_bytes=384 * 1024 * 1024)
    return bundle


def build_command(workspace: str | Path, agent_argv: Sequence[str], bwrap: str | None = None,
                  *, runtime_executable: str | Path | None = None,
                  native_bundle: str | Path | None = None) -> list[str]:
    root = _workspace(workspace)
    if not agent_argv or not all(isinstance(x, str) and x and "\x00" not in x for x in agent_argv):
        raise ValueError("nonempty agent argv of strings is required")
    if not agent_argv[0].startswith("/usr/bin/") and not agent_argv[0].startswith("/bin/"):
        raise ValueError("agent executable must be an absolute /usr/bin or /bin path inside sandbox")
    binary = bwrap or _bwrap_binary()
    cmd = [binary, "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
           "--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp",
           "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8"]
    # Deliberately do NOT bind /home, /root, /etc, /var, host /tmp, /run,
    # local sockets, SSH agent, or the project git checkout.
    for path in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(path).is_dir():
            cmd += ["--ro-bind", path, path]
    cmd += ["--proc", "/proc", "--dev", "/dev",
            "--perms", "1777", "--size", "67108864", "--tmpfs", "/tmp",
            "--perms", "0700", "--size", "8388608", "--tmpfs", "/run", "--dir", "/work", "--ro-bind", str(root), "/work"]
    if runtime_executable is not None or native_bundle is not None:
        cmd += ["--dir", "/opt"]
    if runtime_executable is not None:
        runtime = _runtime_executable(runtime_executable, root)
        cmd.extend(["--ro-bind", str(runtime), "/opt/asg-omp"])
    if native_bundle is not None:
        natives = _native_bundle(native_bundle, root)
        # Read-only versioned addon copy; never bind ~/.omp or arbitrary directories.
        cmd.extend(["--ro-bind", str(natives), "/opt/asg-omp-natives"])
    cmd += ["--chdir", "/work", "--", *agent_argv]
    return cmd


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
    proc.wait(timeout=5)


def run_child(workspace: str | Path, agent_argv: Sequence[str], *, timeout: float = 15,
              runtime_executable: str | Path | None = None,
              native_bundle: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    """A non-MCP diagnostic invocation, with bounded time and no network."""
    if not (0 < timeout <= 120):
        raise ValueError("timeout must be within 1..120 seconds")
    return subprocess.run(build_command(workspace, agent_argv, runtime_executable=runtime_executable,
                                        native_bundle=native_bundle), timeout=timeout,
                          capture_output=True, text=True, env=_minimal_env(),
                          start_new_session=True, check=False)


def _pump(source: IO[bytes], dest: IO[bytes], failures: list[str]) -> None:
    try:
        while True:
            line = source.readline(131074)
            if not line:
                break
            if len(line) > 131073 or not line.endswith(b"\n"):
                raise ValueError("oversized or unterminated MCP frame")
            dest.write(line)
            dest.flush()
    except (BrokenPipeError, OSError, ValueError) as exc:
        # Broken pipe after a peer exits is normal; other errors invalidate run.
        if not isinstance(exc, BrokenPipeError):
            failures.append(type(exc).__name__)
    finally:
        try:
            dest.close()
        except OSError:
            pass


def _drain_child_stderr(source: IO[bytes], captured: list[bytes]) -> None:
    """Drain untrusted child diagnostics without blocking or unbounded memory."""
    tail = b""
    try:
        while True:
            part = source.read(4096)
            if not part:
                break
            tail = (tail + part)[-12288:]
    except OSError:
        pass
    finally:
        captured.append(tail)
        source.close()


def run_mcp_bridge(workspace: str | Path, state_db: str | Path,
                   agent_argv: Sequence[str], *, timeout: float = 20,
                   repo_root: str | Path | None = None,
                   runtime_executable: str | Path | None = None,
                   native_bundle: str | Path | None = None,
                   diagnostics: dict[str, str] | None = None) -> tuple[int, int]:
    """Run a sandboxed MCP-client child, relaying its stdio to trusted M3 MCP.

    No tool access other than the host MCP server is granted. The child still
    can execute subprocesses INSIDE its isolated namespace. If its argv is a
    generic model client that does not speak MCP JSON lines over stdio, this
    bridge is NOT compatible; integration is explicit and opt-in.
    """
    if not (0 < timeout <= 120):
        raise ValueError("timeout must be within 1..120 seconds")
    root = _workspace(workspace)
    db = _state_path(state_db, root)
    repo = Path(repo_root).resolve() if repo_root else Path(__file__).resolve().parents[1]
    if not (repo / "gateway" / "mcp_stdio.py").is_file():
        raise SandboxUnavailable("trusted M3 MCP gateway source is unavailable")
    binary_command = build_command(root, agent_argv, runtime_executable=runtime_executable,
                                   native_bundle=native_bundle)
    db.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    broker_env = _minimal_env()
    broker_env.update({"ASG_MCP_ROOT": str(root), "ASG_MCP_DB_PATH": str(db),
                       "ASG_MCP_ALLOWED_HOSTS": "", "PYTHONUNBUFFERED": "1"})
    broker = subprocess.Popen([sys.executable, "-m", "gateway.mcp_stdio"],
                              cwd=repo, env=broker_env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    child = None
    failures: list[str] = []
    try:
        child = subprocess.Popen(binary_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE if diagnostics is not None else subprocess.DEVNULL,
                                 env=_minimal_env(), start_new_session=True)
        stderr_capture: list[bytes] = []
        stderr_thread = None
        if diagnostics is not None:
            stderr_thread = threading.Thread(target=_drain_child_stderr,
                                             args=(child.stderr, stderr_capture), daemon=True)
            stderr_thread.start()
        to_broker = threading.Thread(target=_pump, args=(child.stdout, broker.stdin, failures), daemon=True)
        to_child = threading.Thread(target=_pump, args=(broker.stdout, child.stdin, failures), daemon=True)
        to_broker.start()
        to_child.start()
        try:
            child_code = child.wait(timeout=timeout)
            to_broker.join(timeout=3)
            if to_broker.is_alive():
                raise SandboxUnavailable("MCP child->broker channel did not close")
            broker_code = broker.wait(timeout=5)
            to_child.join(timeout=3)
            if to_child.is_alive():
                raise SandboxUnavailable("MCP broker->child channel did not close")
            if stderr_thread is not None:
                stderr_thread.join(timeout=3)
                if stderr_thread.is_alive():
                    raise SandboxUnavailable("sandbox diagnostics channel failed to close")
                diagnostics["child_stderr_tail"] = (stderr_capture[0] if stderr_capture else b"").decode("utf-8", "replace")
            if failures:
                raise SandboxUnavailable("MCP framing/transport invalid: " + ",".join(failures))
            return child_code, broker_code
        except subprocess.TimeoutExpired as exc:
            raise SandboxUnavailable("MCP execution or shutdown timed out") from exc
    finally:
        if child is not None:
            _terminate(child)
        _terminate(broker)


def main() -> int:
    ap = argparse.ArgumentParser(description="M4 isolated POSIX child, trusted MCP outside namespace")
    ap.add_argument("--workspace", required=True, help="explicit directory visible read-only as /work")
    ap.add_argument("--state-db", required=True, help="trusted MCP state SQLite outside workspace")
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- /usr/bin/python3 /work/agent.py")
    args = ap.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    try:
        child_rc, broker_rc = run_mcp_bridge(args.workspace, args.state_db, command, timeout=args.timeout)
    except (SandboxUnavailable, ValueError, OSError) as exc:
        print("FAIL: M4 sandbox: " + str(exc), file=sys.stderr)
        return 2
    if child_rc or broker_rc:
        print(f"FAIL: isolated agent={child_rc}; trusted MCP broker={broker_rc}", file=sys.stderr)
        return 1
    print("PASS: isolated child and mediated MCP channel completed (not a universal sandbox proof)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
