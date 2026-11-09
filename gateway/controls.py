from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional, Tuple

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


@dataclass(frozen=True)
class GatewayRuntimeConfig:
    auth_enabled: bool = False
    auth_header: str = "x-api-key"
    api_keys: Tuple[str, ...] = ()
    operator_api_keys: Tuple[str, ...] = ()
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60

    def validate(self) -> None:
        if self.rate_limit_requests < 1:
            raise ValueError("rate_limit_requests must be >= 1")
        if self.rate_limit_window_seconds < 1:
            raise ValueError("rate_limit_window_seconds must be >= 1")
        if self.auth_enabled and not self.api_keys:
            raise ValueError("auth is enabled but no API keys are configured")
        if set(self.api_keys) & set(self.operator_api_keys):
            raise ValueError("agent and operator API keys must not overlap")


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[Tuple[str, str, int], int] = {}
        self._generic: Dict[str, int] = {}

    def inc_http(self, method: str, path: str, status_code: int) -> None:
        key = (method.upper(), path, int(status_code))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._generic[name] = self._generic.get(name, 0) + int(value)

    def render_prometheus(self) -> str:
        lines = [
            "# HELP gateway_http_requests_total Total HTTP requests by method/path/status",
            "# TYPE gateway_http_requests_total counter",
        ]
        with self._lock:
            for (method, path, status), count in sorted(self._counters.items()):
                lines.append(
                    f'gateway_http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}'
                )
            lines.append("# HELP gateway_events_total Gateway internal event counters")
            lines.append("# TYPE gateway_events_total counter")
            for name, count in sorted(self._generic.items()):
                lines.append(f'gateway_events_total{{name="{name}"}} {count}')
        return "\n".join(lines) + "\n"


class DeterministicRateLimiter:
    def __init__(
        self,
        *,
        requests_per_window: int,
        window_seconds: int,
        now_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.now_fn = now_fn or time.time
        self._lock = threading.Lock()
        self._state: Dict[str, Tuple[int, int]] = {}

    def allow(self, key: str) -> bool:
        now = int(self.now_fn())
        bucket = now // self.window_seconds
        with self._lock:
            current_bucket, count = self._state.get(key, (bucket, 0))
            if current_bucket != bucket:
                current_bucket = bucket
                count = 0
            if count >= self.requests_per_window:
                self._state[key] = (current_bucket, count)
                return False
            count += 1
            self._state[key] = (current_bucket, count)
            return True


class GatewayGuardMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        config: GatewayRuntimeConfig,
        metrics: MetricsRegistry,
        rate_limiter: Optional[DeterministicRateLimiter] = None,
        exempt_paths: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(app)
        self.config = config
        self.metrics = metrics
        self.rate_limiter = rate_limiter
        self.exempt_paths = set(exempt_paths or {"/health", "/ready"})

    def _is_exempt(self, path: str) -> bool:
        if path in self.exempt_paths:
            return True
        return any(path.startswith(prefix + "/") for prefix in self.exempt_paths)

    def _auth_error(self, message: str, status_code: int = 401) -> JSONResponse:
        self.metrics.inc("auth_denied")
        return JSONResponse(
            status_code=status_code,
            content={"error": message, "code": "auth_failed", "details": None},
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if self._is_exempt(path):
            response = await call_next(request)
            self.metrics.inc_http(request.method, path, response.status_code)
            return response

        provided_key = request.headers.get(self.config.auth_header, "")
        operator_only = path == "/approval/resolve" or path == "/operator" or path.startswith("/operator/")
        if operator_only:
            # Fail closed even in unauthenticated local development mode.
            if not self.config.operator_api_keys:
                response = self._auth_error("operator credentials are not configured", status_code=503)
                self.metrics.inc_http(request.method, path, response.status_code)
                return response
            if not any(secrets.compare_digest(provided_key.encode("utf-8"), key.encode("utf-8")) for key in self.config.operator_api_keys):
                response = self._auth_error("operator API key required", status_code=401 if not provided_key else 403)
                self.metrics.inc_http(request.method, path, response.status_code)
                return response
        elif self.config.auth_enabled:
            if not self.config.api_keys:
                response = self._auth_error("gateway auth misconfigured", status_code=503)
                self.metrics.inc_http(request.method, path, response.status_code)
                return response
            if not any(secrets.compare_digest(provided_key.encode("utf-8"), key.encode("utf-8")) for key in self.config.api_keys):
                response = self._auth_error("missing or invalid API key", status_code=401)
                self.metrics.inc_http(request.method, path, response.status_code)
                return response

        if self.config.rate_limit_enabled and self.rate_limiter is not None:
            client_host = request.client.host if request.client else "unknown"
            limiter_key = provided_key or client_host
            if not self.rate_limiter.allow(limiter_key):
                self.metrics.inc("rate_limited")
                response = JSONResponse(
                    status_code=429,
                    content={"error": "rate limit exceeded", "code": "rate_limited", "details": None},
                )
                self.metrics.inc_http(request.method, path, response.status_code)
                return response

        response = await call_next(request)
        self.metrics.inc_http(request.method, path, response.status_code)
        return response
