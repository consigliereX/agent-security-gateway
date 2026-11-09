#!/usr/bin/env python3
"""M4 live Linux namespace acceptance: offline synthetic agents only.

Requires working unprivileged bubblewrap; no network access, host runtime
configuration changes, real user files, or real OMP/Claude Code agent.
Records are generated on the host after verifying irreversible boundaries.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from gateway.os_sandbox import SandboxUnavailable, _bwrap_binary, run_child, run_mcp_bridge


OS_PROBE = r'''
import json, os, socket, subprocess, sys, tempfile
from pathlib import Path
secret = Path(sys.argv[1]); port = int(sys.argv[2])
checks = {}
checks["host_private_file_hidden"] = not secret.exists()
checks["host_home_hidden"] = not Path(sys.argv[3]).exists()
checks["env_scrubbed"] = "ASG_M4_PRIVATE_CANARY" not in os.environ and "SSH_AUTH_SOCK" not in os.environ
checks["new_user_namespace"] = os.readlink("/proc/self/ns/user") != sys.argv[4]
checks["new_network_namespace"] = os.readlink("/proc/self/ns/net") != sys.argv[5]
checks["new_pid_namespace"] = os.readlink("/proc/self/ns/pid") != sys.argv[6]
checks["workspace_readable"] = Path("/work/marker.txt").read_text() == "unaltered"
try:
    Path("/work/marker.txt").write_text("DIRECT MODIFICATION")
    checks["workspace_direct_write_denied"] = False
except OSError:
    checks["workspace_direct_write_denied"] = True
try:
    Path("/work/unauthorized.txt").write_text("DIRECT MODIFICATION")
    checks["workspace_new_write_denied"] = False
except OSError:
    checks["workspace_new_write_denied"] = True
proc = subprocess.run(["/usr/bin/python3", "-c",
   "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('ESCAPED')", str(secret)],
   capture_output=True, timeout=4)
checks["unmediated_subprocess_host_write_denied"] = proc.returncode != 0
try:
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        checks["loopback_egress_denied"] = False
except OSError:
    checks["loopback_egress_denied"] = True
try:
    with tempfile.NamedTemporaryFile(prefix="asg-m4-") as f:
        f.write(b"OK"); f.flush()
        checks["private_tmpfs_usable"] = Path(f.name).read_bytes() == b"OK"
except OSError:
    checks["private_tmpfs_usable"] = False
print(json.dumps(checks, sort_keys=True))
sys.exit(0 if all(checks.values()) else 3)
'''

MCP_AGENT = r'''
import json, os, sys
from pathlib import Path
counter = 0

def request(method, params=None):
    global counter
    counter += 1
    sys.stdout.write(json.dumps({"jsonrpc":"2.0", "id":counter, "method":method, "params":params or {}}, separators=(",", ":"))+"\n")
    sys.stdout.flush()
    raw = sys.stdin.readline()
    if not raw: raise RuntimeError("trusted MCP broker disconnected")
    answer = json.loads(raw)
    if answer.get("id") != counter: raise RuntimeError("RPC reply id mismatch")
    return answer

def tool(name, args): return request("tools/call", {"name":name,"arguments":args})

assert "result" in request("initialize", {"protocolVersion":"2025-06-18"})
sys.stdout.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
sys.stdout.flush()
listed = request("tools/list")
assert {entry["name"] for entry in listed["result"]["tools"]} == {"asg_read_file", "asg_write_file"}
assert tool("asg_write_file", {"path":"mediated.txt", "content":"MCP_OK"})["result"]["isError"] is False
read = tool("asg_read_file", {"path":"mediated.txt"})
assert read["result"]["content"][0]["text"] == "MCP_OK"
assert tool("asg_write_file", {"path":"../escape.txt", "content":"BAD"})["result"]["isError"]
assert "error" in tool("run_shell", {"command":"id"})
assert "error" in tool("asg_http_get", {"url":"http://127.0.0.1"})
try:
    Path("/work/direct-write.txt").write_text("BYPASS")
except OSError:
    pass
else:
    raise AssertionError("unmediated workspace write succeeded")
'''


def demand(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def verify() -> dict:
    bwrap = _bwrap_binary()
    version = subprocess.run([bwrap, "--version"], capture_output=True, text=True, timeout=4)
    demand(version.returncode == 0, "bubblewrap --version failed")
    cases: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="asg-m4-") as td:
        home = Path(td)
        work = home / "workspace"
        work.mkdir(mode=0o700)
        marker = work / "marker.txt"
        marker.write_text("unaltered", encoding="utf-8")
        secret = home / "private-canary.txt"
        secret.write_text(secrets.token_hex(32), encoding="utf-8")
        original_secret = secret.read_text()
        (work / "os_probe.py").write_text(OS_PROBE, encoding="utf-8")
        (work / "mcp_agent.py").write_text(MCP_AGENT, encoding="utf-8")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            namespaces = [os.readlink("/proc/self/ns/" + kind) for kind in ("user", "net", "pid")]
            # A real control plane is not present in this untrusted process.
            # The listener proves a shared host network namespace would be reachable.
            command = ["/usr/bin/python3", "/work/os_probe.py", str(secret),
                       str(listener.getsockname()[1]), str(Path.home()), *namespaces]
            # Deliberately verify private environment values are not exposed.
            os.environ["ASG_M4_PRIVATE_CANARY"] = "DO_NOT_EXPOSE"
            try:
                probe = run_child(work, command, timeout=15)
            finally:
                os.environ.pop("ASG_M4_PRIVATE_CANARY", None)
        demand(probe.returncode == 0, "OS namespace probe failed (rc=%s, err=%s)" %
               (probe.returncode, probe.stderr[-500:]))
        try:
            observations = json.loads(probe.stdout.strip())
        except ValueError as exc:
            raise RuntimeError("namespace probe did not return valid evidence") from exc
        expected = {"host_private_file_hidden", "host_home_hidden", "env_scrubbed",
                    "new_user_namespace", "new_network_namespace", "new_pid_namespace",
                    "workspace_readable", "workspace_direct_write_denied",
                    "workspace_new_write_denied", "unmediated_subprocess_host_write_denied",
                    "loopback_egress_denied", "private_tmpfs_usable"}
        demand(set(observations) == expected, "OS probe evidence keys mismatch")
        for name, ok in observations.items():
            demand(ok is True, "OS sandbox escape: " + name)
            cases.append({"test": name, "status": "PASS"})
        demand(marker.read_text() == "unaltered" and not (work / "unauthorized.txt").exists(),
               "host workspace was modified directly")
        demand(secret.read_text() == original_secret, "host private canary was modified")
        cases.append({"test": "host_side_canaries_unchanged", "status": "PASS"})

        db = home / "private-db" / "mcp.sqlite3"
        child_rc, broker_rc = run_mcp_bridge(work, db,
                                             ["/usr/bin/python3", "/work/mcp_agent.py"], timeout=20)
        demand(child_rc == 0 and broker_rc == 0, "sandbox MCP bridge returned nonzero rc")
        demand((work / "mediated.txt").read_text() == "MCP_OK", "trusted MCP write was not observed")
        demand(not (work / "direct-write.txt").exists(), "direct workspace write escaped")
        demand(not (home / "escape.txt").exists(), "MCP path traversal escaped")
        demand(db.is_file(), "trusted MCP state database was not written")
        cases.extend([{"test": "broker_mcp_stdio_roundtrip", "status": "PASS"},
                      {"test": "read_only_workspace_direct_bypass_denied", "status": "PASS"},
                      {"test": "mediated_write_visible_to_host", "status": "PASS"}])
        with sqlite3.connect(db) as conn:
            events = conn.execute("SELECT action_type, decision FROM audit_events").fetchall()
        demand(any(a == "write_filesystem" and d == "allow" for a, d in events),
               "missing trusted broker allow audit for file write")
        demand(any(a == "read_filesystem" and d in {"allow", "allow_with_redaction"} for a, d in events),
               "missing trusted broker read audit")
        cases.append({"test": "trusted_broker_audit_persisted", "status": "PASS"})
        demand(secret.read_text() == original_secret, "host canary modified after MCP bridge")
    return {"timestamp": datetime.now(timezone.utc).isoformat(),
            "scope": "unprivileged bubblewrap child, host-side trusted MCP stdio; synthetic agent",
            "bubblewrap_version": version.stdout.strip()[:90],
            "tested_with_actual_omp": False,
            "tested_with_actual_claude_code": False,
            "host_network_namespace_unshared": True,
            "host_workspace_direct_writes_blocked": True,
            "cases": cases, "pass_count": len(cases), "fail_count": 0,
            "verdict": "SANDBOXED_SYNTHETIC_AGENT_AND_MEDIATED_MCP_PASS__REAL_AGENT_UNTESTED"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, default=Path(".git/security-m4-evidence.json"))
    args = ap.parse_args()
    try:
        output = verify()
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (SandboxUnavailable, OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print("FAIL: M4 live sandbox proof: " + str(exc), file=sys.stderr)
        return 2
    print(f"PASS: {output['pass_count']} live OS/MCP sandbox checks")
    print("PASS: host file and network escapes denied; trusted MCP broker functioning")
    print("EVIDENCE: " + str(args.evidence.resolve()))
    print("RESULT: synthetic child sandbox validated; actual OMP/Claude Code not tested")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
