"""Restricted stdio MCP tool adapter, not a process/OS sandbox.

Only the listed tools are exposed; all I/O uses Agent Security Gateway's
existing guarded adapters. The owning agent runtime MUST disable any other
unmediated shell, filesystem and network tools to make mediation meaningful.

Start with ASG_MCP_ROOT=/absolute/isolated/folder python -m gateway.mcp_stdio
Never place SQLite state inside ASG_MCP_ROOT.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from firewall.adapters import AdapterContext, FileSystemAdapter, HttpAdapter, ToolExecutionDenied
from firewall.api import create_firewall
from firewall.approval_store import SQLiteApprovalStore
from firewall.audit_store import SQLiteAuditStore
from firewall.session_store import SQLiteSessionRiskStore
from gateway.service import GatewayInspectionService

MAX_MESSAGE_BYTES = 131072
MAX_WRITE_BYTES = 16384
MAX_TOOL_CALLS = 128
SUPPORTED_PROTOCOL = "2025-06-18"


def _tool(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties,
                            "required": required, "additionalProperties": False}}


BASE_TOOLS = (
    _tool("asg_read_file", "Read a UTF-8 file under the configured isolated workspace; no symlink traversal.",
          {"path": {"type": "string", "minLength": 1}}, ["path"]),
    _tool("asg_write_file", "Write a small UTF-8 file inside the isolated workspace; subject to gateway policy.",
          {"path": {"type": "string", "minLength": 1},
           "content": {"type": "string", "maxLength": MAX_WRITE_BYTES}}, ["path", "content"]),
)
HTTP_TOOL = _tool("asg_http_get", "GET an explicitly allowlisted host through the policy-enforced HTTP adapter.",
                  {"url": {"type": "string", "minLength": 1}}, ["url"])


class MCPGateway:
    """Stdio protocol state for one connected agent process."""

    def __init__(self, root: Path, db_path: Path, allowed_hosts: tuple[str, ...] = ()) -> None:
        if not root.is_absolute() or not root.is_dir():
            raise ValueError("ASG_MCP_ROOT must be an existing absolute directory")
        root = root.resolve()
        db_path = db_path.expanduser().resolve()
        if db_path == root or root in db_path.parents:
            raise ValueError("gateway state database must be outside ASG_MCP_ROOT")
        db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.session_id = "mcp-" + secrets.token_urlsafe(18)
        self.agent_id = "mcp-stdio"
        self.turn = 0
        self.tool_calls = 0
        self.initialized = False
        self.allowed_hosts = tuple(allowed_hosts)
        self.session_store = SQLiteSessionRiskStore(str(db_path))
        self.approval_store = SQLiteApprovalStore(str(db_path))
        self.audit_store = SQLiteAuditStore(str(db_path))
        self.service = GatewayInspectionService(
            firewall=create_firewall(),
            session_store=self.session_store,
            approval_store=self.approval_store,
            audit_store=self.audit_store,
        )
        self.fs = FileSystemAdapter(service=self.service, base_dir=str(root), max_bytes=MAX_WRITE_BYTES)
        self.http = HttpAdapter(service=self.service, allowed_hosts=allowed_hosts,
                                timeout_seconds=3.0, max_response_chars=4096)

    def close(self) -> None:
        for store in (self.audit_store, self.approval_store, self.session_store):
            store.close()

    def tools(self) -> list[dict]:
        return [*BASE_TOOLS, *([HTTP_TOOL] if self.allowed_hosts else [])]

    def _context(self) -> AdapterContext:
        self.turn += 1
        return AdapterContext(session_id=self.session_id, agent_id=self.agent_id,
                              turn_id=str(self.turn), user_input="MCP mediated tool invocation")

    @staticmethod
    def _result(text: str, is_error: bool = False) -> dict:
        return {"content": [{"type": "text", "text": text}], "isError": is_error}

    @staticmethod
    def _require(args: Any, required: tuple[str, ...]) -> dict:
        if not isinstance(args, dict) or set(args) != set(required):
            raise ValueError("exact declared tool arguments required")
        if not all(isinstance(args[k], str) for k in required):
            raise ValueError("tool arguments must be strings")
        if any("\x00" in args[k] for k in required):
            raise ValueError("null byte in tool argument")
        return args

    def call_tool(self, name: Any, args: Any) -> dict:
        self.tool_calls += 1
        if self.tool_calls > MAX_TOOL_CALLS:
            return self._result("DENIED: tool call budget exhausted", True)
        # Every call must go through a declared adapter; there is no subprocess,
        # filesystem built-in, or approval-resolve escape hatch in this MCP server.
        if not isinstance(name, str) or name not in {tool["name"] for tool in self.tools()}:
            raise KeyError("unknown or disabled tool")
        try:
            if name == "asg_read_file":
                data = self._require(args, ("path",))
                text = self.fs.read_text(data["path"], self._context())
                return self._result(text)
            if name == "asg_write_file":
                data = self._require(args, ("path", "content"))
                if len(data["content"].encode("utf-8")) > MAX_WRITE_BYTES:
                    raise ValueError("content exceeds byte limit")
                self.fs.write_text(data["path"], data["content"], self._context())
                return self._result("OK: write completed through gateway")
            data = self._require(args, ("url",))
            text = self.http.request("GET", data["url"], self._context())
            return self._result(text)
        except ToolExecutionDenied as exc:
            decision = exc.decision
            approval = decision.get("approval") or {}
            extra = (" approval_id=" + str(approval["approval_id"])) if approval.get("approval_id") else ""
            return self._result("DENIED: gateway decision=" + str(decision.get("decision", "unknown")) + extra, True)
        except (ValueError, OSError, UnicodeError) as exc:
            return self._result("DENIED: invalid path, policy, or I/O (" + exc.__class__.__name__ + ")", True)

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _response(request_id: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def handle(self, request: Any) -> dict | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid JSON-RPC request")
        method = request.get("method")
        if not isinstance(method, str):
            return self._error(request.get("id"), -32600, "Method must be a string")
        if "id" not in request:
            # Client notifications never get replies.
            if method == "notifications/initialized":
                self.initialized = True
            return None
        request_id = request["id"]
        if not isinstance(request_id, (int, str)) or isinstance(request_id, bool):
            return self._error(None, -32600, "Invalid request id")
        params = request.get("params", {})
        if not isinstance(params, dict):
            return self._error(request_id, -32602, "Invalid params")
        if method == "initialize":
            if "protocolVersion" not in params:
                return self._error(request_id, -32602, "Protocol version required")
            return self._response(request_id, {
                "protocolVersion": SUPPORTED_PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agent-security-gateway-stdio", "version": "0.3.0-m3"},
            })
        if not self.initialized:
            return self._error(request_id, -32000, "MCP initialize handshake required")
        if method == "ping":
            return self._response(request_id, {})
        if method == "tools/list":
            if params.get("cursor"):
                return self._error(request_id, -32602, "Invalid pagination cursor")
            return self._response(request_id, {"tools": self.tools()})
        if method == "tools/call":
            try:
                result = self.call_tool(params.get("name"), params.get("arguments", {}))
            except KeyError:
                return self._error(request_id, -32602, "Unknown or disabled tool")
            return self._response(request_id, result)
        return self._error(request_id, -32601, "Method not found")


def main() -> int:
    raw_root = os.environ.get("ASG_MCP_ROOT", "")
    if not raw_root:
        print("ASG_MCP_ROOT must be set to an isolated absolute directory", file=sys.stderr)
        return 2
    root = Path(raw_root).expanduser()
    state_base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))).expanduser()
    db = Path(os.environ.get("ASG_MCP_DB_PATH", str(state_base / "agent-security-gateway/mcp.sqlite3")))
    hosts = tuple(sorted({v.strip().lower() for v in os.environ.get("ASG_MCP_ALLOWED_HOSTS", "").split(",") if v.strip()}))
    try:
        server = MCPGateway(root, db, hosts)
    except (ValueError, OSError, RuntimeError) as exc:
        print("MCP startup denied: " + str(exc), file=sys.stderr)
        return 2
    try:
        while True:
            line = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
                print(json.dumps(server._error(None, -32600, "Message too large"), separators=(",", ":")), flush=True)
                return 2
            try:
                request = json.loads(line)
            except (UnicodeError, ValueError):
                response = server._error(None, -32700, "Parse error")
            else:
                try:
                    response = server.handle(request)
                except Exception as exc:
                    print("MCP internal error: " + exc.__class__.__name__, file=sys.stderr)
                    response = server._error(request.get("id") if isinstance(request, dict) else None, -32603, "Internal error")
            if response is not None:
                print(json.dumps(response, separators=(",", ":"), ensure_ascii=False), flush=True)
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
