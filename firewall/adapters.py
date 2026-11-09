from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib import error as url_error
from urllib import request as url_request
from urllib.parse import urlparse

from gateway.service import GatewayInspectionService

from .logging_utils import get_logger
from .types import PlannedAction


class ToolExecutionDenied(RuntimeError):
    def __init__(self, message: str, decision: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.decision = dict(decision)


@dataclass(frozen=True)
class AdapterContext:
    session_id: str = ""
    turn_id: str = ""
    agent_id: str = ""
    user_input: str = ""
    approval_token: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class _BaseAdapter:
    def __init__(self, service: GatewayInspectionService, adapter_name: str) -> None:
        self.service = service
        self.adapter_name = adapter_name
        self.logger = get_logger(name=f"gateway.adapter.{adapter_name}", structured=True)

    def _inspect(
        self,
        *,
        context: AdapterContext,
        planned_actions: Sequence[PlannedAction],
        memory_reads: Sequence[str],
        memory_writes: Sequence[str],
        model_output: str = "",
        redaction: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        decision = self.service.inspect(
            user_input=context.user_input,
            model_output=model_output,
            planned_actions=list(planned_actions),
            memory_reads=list(memory_reads),
            memory_writes=list(memory_writes),
            session_id=context.session_id,
            turn_id=context.turn_id,
            agent_id=context.agent_id,
            approval_token=context.approval_token,
            gateway_metadata={"adapter": self.adapter_name, **dict(context.metadata)},
            redaction=redaction,
        )
        return decision

    def _sanitize_output(self, value: str) -> Tuple[str, Dict[str, Any]]:
        if hasattr(self.service, "sanitize_output"):
            return self.service.sanitize_output(value)
        return value, {"redacted": False, "masked_count": 0, "items": []}

    def _enforce_pre(self, decision: Mapping[str, Any]) -> None:
        outcome = str(decision.get("decision", "")).lower()
        if outcome in {"allow", "allow_with_redaction"}:
            return
        if outcome == "require_approval":
            raise ToolExecutionDenied("pre-execution requires human approval", decision)
        if outcome == "block":
            raise ToolExecutionDenied("pre-execution blocked by gateway", decision)
        if outcome == "challenge":
            raise ToolExecutionDenied("pre-execution requires challenge/approval", decision)
        raise ToolExecutionDenied(f"unsupported decision outcome: {outcome}", decision)

    def _audit(self, event: str, fields: Mapping[str, Any]) -> None:
        self.logger.info(
            event,
            extra={"extra_fields": {"event": event, **dict(fields)}},
        )


class ShellAdapter(_BaseAdapter):
    def __init__(
        self,
        service: GatewayInspectionService,
        allowed_executables: Iterable[str],
        timeout_seconds: float = 5.0,
        max_output_chars: int = 4000,
    ) -> None:
        super().__init__(service=service, adapter_name="shell")
        self.allowed_executables = {str(x).strip().lower() for x in allowed_executables if str(x).strip()}
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    def run(self, command: Sequence[str], context: AdapterContext) -> subprocess.CompletedProcess[str]:
        if not command:
            raise ValueError("command cannot be empty")
        executable = str(command[0]).strip().lower()
        if executable not in self.allowed_executables:
            raise ValueError("executable not allowed")

        # Inspect and fingerprint the exact argv that will execute. JSON is
        # unambiguous for arguments containing whitespace or quotes.
        argv = [str(part) for part in command]
        action = PlannedAction(action_type="exec_shell", target=json.dumps(argv, ensure_ascii=False, separators=(",", ":")))
        pre = self._inspect(context=context, planned_actions=[action], memory_reads=[], memory_writes=[])
        self._enforce_pre(pre)

        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            shell=False,
            check=False,
        )
        bounded_stdout = proc.stdout[: self.max_output_chars]
        bounded_stderr = proc.stderr[: self.max_output_chars]

        safe_stdout, redaction_stdout = self._sanitize_output(bounded_stdout)
        safe_stderr, redaction_stderr = self._sanitize_output(bounded_stderr)
        redaction = {
            "redacted": bool(redaction_stdout.get("redacted") or redaction_stderr.get("redacted")),
            "masked_count": int(redaction_stdout.get("masked_count", 0)) + int(redaction_stderr.get("masked_count", 0)),
            "items": list(redaction_stdout.get("items", [])) + list(redaction_stderr.get("items", [])),
        }

        post = self._inspect(
            context=context,
            planned_actions=[action],
            memory_reads=[],
            memory_writes=[],
            model_output=f"exit={proc.returncode}\nstdout={safe_stdout}\nstderr={safe_stderr}",
            redaction=redaction,
        )

        self._audit(
            "tool_shell_execution",
            {
                "decision_pre": pre.get("decision"),
                "decision_post": post.get("decision"),
                "returncode": proc.returncode,
                "executable": executable,
                "argv_count": len(argv),
                "command_sha256": hashlib.sha256(action.target.encode("utf-8")).hexdigest(),
                "session_id": context.session_id,
                "turn_id": context.turn_id,
                "agent_id": context.agent_id,
                "redacted": redaction.get("redacted", False),
                "masked_count": redaction.get("masked_count", 0),
            },
        )
        return subprocess.CompletedProcess(proc.args, proc.returncode, safe_stdout, safe_stderr)


class FileSystemAdapter(_BaseAdapter):
    def __init__(self, service: GatewayInspectionService, base_dir: str, max_bytes: int = 65536) -> None:
        super().__init__(service=service, adapter_name="filesystem")
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes

    def _resolve(self, relative_path: str) -> Path:
        candidate = (self.base_dir / relative_path).resolve()
        if self.base_dir not in candidate.parents and candidate != self.base_dir:
            raise ValueError("path escapes base directory")
        return candidate

    def read_text(self, relative_path: str, context: AdapterContext) -> str:
        target = self._resolve(relative_path)
        action = PlannedAction(action_type="read_filesystem", target=str(target))
        pre = self._inspect(context=context, planned_actions=[action], memory_reads=[str(target)], memory_writes=[])
        self._enforce_pre(pre)

        data = target.read_text(encoding="utf-8")
        bounded = data[: self.max_bytes]
        safe, redaction = self._sanitize_output(bounded)

        post = self._inspect(
            context=context,
            planned_actions=[action],
            memory_reads=[str(target)],
            memory_writes=[],
            model_output=safe,
            redaction=redaction,
        )
        self._audit(
            "tool_filesystem_read",
            {
                "decision_pre": pre.get("decision"),
                "decision_post": post.get("decision"),
                "path": str(target),
                "bytes": len(safe.encode("utf-8")),
                "session_id": context.session_id,
                "redacted": redaction.get("redacted", False),
                "masked_count": redaction.get("masked_count", 0),
            },
        )
        return safe

    def write_text(self, relative_path: str, content: str, context: AdapterContext) -> None:
        payload = content[: self.max_bytes]
        target = self._resolve(relative_path)
        action = PlannedAction(action_type="write_filesystem", target=str(target))
        pre = self._inspect(context=context, planned_actions=[action], memory_reads=[], memory_writes=[str(target)])
        self._enforce_pre(pre)

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")

        post = self._inspect(
            context=context,
            planned_actions=[action],
            memory_reads=[],
            memory_writes=[str(target)],
            model_output=f"wrote {len(payload.encode('utf-8'))} bytes",
        )
        self._audit(
            "tool_filesystem_write",
            {
                "decision_pre": pre.get("decision"),
                "decision_post": post.get("decision"),
                "path": str(target),
                "bytes": len(payload.encode("utf-8")),
                "session_id": context.session_id,
            },
        )


class HttpAdapter(_BaseAdapter):
    def __init__(
        self,
        service: GatewayInspectionService,
        allowed_hosts: Iterable[str],
        timeout_seconds: float = 5.0,
        max_response_chars: int = 4000,
    ) -> None:
        super().__init__(service=service, adapter_name="http")
        self.allowed_hosts = {str(h).strip().lower() for h in allowed_hosts if str(h).strip()}
        self.timeout_seconds = timeout_seconds
        self.max_response_chars = max_response_chars

    def request(self, method: str, url: str, context: AdapterContext, body: str = "") -> str:
        method_upper = method.upper().strip()
        if method_upper not in {"GET", "POST"}:
            raise ValueError("only GET and POST are allowed")
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host not in self.allowed_hosts:
            raise ValueError("host is not allowed")

        action = PlannedAction(action_type="network_exfiltration", target=url)
        pre = self._inspect(context=context, planned_actions=[action], memory_reads=[], memory_writes=[])
        self._enforce_pre(pre)

        req = url_request.Request(url=url, method=method_upper)
        if method_upper == "POST":
            req.data = body.encode("utf-8")
            req.add_header("Content-Type", "text/plain; charset=utf-8")

        try:
            with url_request.urlopen(req, timeout=self.timeout_seconds) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except url_error.URLError as exc:
            text = f"http_error:{exc.reason}"

        bounded = text[: self.max_response_chars]
        safe, redaction = self._sanitize_output(bounded)
        post = self._inspect(
            context=context,
            planned_actions=[action],
            memory_reads=[],
            memory_writes=[],
            model_output=safe,
            redaction=redaction,
        )
        self._audit(
            "tool_http_request",
            {
                "decision_pre": pre.get("decision"),
                "decision_post": post.get("decision"),
                "method": method_upper,
                "url": url,
                "response_chars": len(safe),
                "session_id": context.session_id,
                "redacted": redaction.get("redacted", False),
                "masked_count": redaction.get("masked_count", 0),
            },
        )
        return safe


class MemoryAdapter(_BaseAdapter):
    def __init__(self, service: GatewayInspectionService, initial: Optional[MutableMapping[str, str]] = None) -> None:
        super().__init__(service=service, adapter_name="memory")
        self._store: MutableMapping[str, str] = initial or {}

    def read(self, key: str, context: AdapterContext) -> Optional[str]:
        action = PlannedAction(action_type="read_memory", target=key)
        pre = self._inspect(context=context, planned_actions=[action], memory_reads=[key], memory_writes=[])
        self._enforce_pre(pre)

        value = self._store.get(key)
        safe, redaction = self._sanitize_output(value or "")
        post = self._inspect(
            context=context,
            planned_actions=[action],
            memory_reads=[key],
            memory_writes=[],
            model_output=safe,
            redaction=redaction,
        )
        self._audit(
            "tool_memory_read",
            {
                "decision_pre": pre.get("decision"),
                "decision_post": post.get("decision"),
                "key": key,
                "found": value is not None,
                "session_id": context.session_id,
                "redacted": redaction.get("redacted", False),
                "masked_count": redaction.get("masked_count", 0),
            },
        )
        if value is None:
            return None
        return safe

    def write(self, key: str, value: str, context: AdapterContext) -> None:
        action = PlannedAction(action_type="write_memory", target=key)
        pre = self._inspect(context=context, planned_actions=[action], memory_reads=[], memory_writes=[key])
        self._enforce_pre(pre)

        self._store[key] = value

        post = self._inspect(
            context=context,
            planned_actions=[action],
            memory_reads=[],
            memory_writes=[key],
            model_output=f"memory_write:{key}",
        )
        self._audit(
            "tool_memory_write",
            {
                "decision_pre": pre.get("decision"),
                "decision_post": post.get("decision"),
                "key": key,
                "value_len": len(value),
                "session_id": context.session_id,
            },
        )
