from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from firewall.api import create_firewall
from firewall.approval_store import SQLiteApprovalStore
from firewall.audit_store import SQLiteAuditStore
from firewall.models import ErrorResponse
from firewall.session_store import SQLiteSessionRiskStore

from .controls import DeterministicRateLimiter, GatewayGuardMiddleware, GatewayRuntimeConfig, MetricsRegistry
from .routes_approval import router as approval_router
from .routes_health import router as health_router
from .routes_inspect import router as inspect_router
from .routes_operator import router as operator_router
from .service import GatewayInspectionService


def _to_dict(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _parse_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean for {name}: {value}")


def _parse_runtime_config() -> GatewayRuntimeConfig:
    auth_enabled = _parse_bool_env("GATEWAY_AUTH_ENABLED", False)
    auth_header = os.getenv("GATEWAY_AUTH_HEADER", "x-api-key").strip().lower()
    keys_raw = os.getenv("GATEWAY_API_KEYS", "")
    api_keys = tuple(sorted({k.strip() for k in keys_raw.split(",") if k.strip()}))
    operator_keys_raw = os.getenv("GATEWAY_OPERATOR_API_KEYS", "")
    operator_api_keys = tuple(sorted({k.strip() for k in operator_keys_raw.split(",") if k.strip()}))

    rl_enabled = _parse_bool_env("GATEWAY_RATE_LIMIT_ENABLED", False)
    rl_requests = int(os.getenv("GATEWAY_RATE_LIMIT_REQUESTS", "120"))
    rl_window = int(os.getenv("GATEWAY_RATE_LIMIT_WINDOW_SECONDS", "60"))

    cfg = GatewayRuntimeConfig(
        auth_enabled=auth_enabled,
        auth_header=auth_header,
        api_keys=api_keys,
        operator_api_keys=operator_api_keys,
        rate_limit_enabled=rl_enabled,
        rate_limit_requests=rl_requests,
        rate_limit_window_seconds=rl_window,
    )
    cfg.validate()
    return cfg


def create_app(
    config_path: str | None = None,
    session_db_path: str | None = None,
    runtime_config: Optional[GatewayRuntimeConfig] = None,
    rate_limiter_now_fn: Optional[Callable[[], float]] = None,
) -> FastAPI:
    app = FastAPI(title="Agent Security Gateway", version="0.5.0")

    effective_config = config_path or os.getenv("FIREWALL_CONFIG")
    effective_session_db = session_db_path or os.getenv("FIREWALL_SESSION_DB", "gateway_sessions.sqlite3")
    effective_runtime = runtime_config or _parse_runtime_config()

    firewall = create_firewall(config_path=effective_config)
    session_store = SQLiteSessionRiskStore(effective_session_db)
    approval_store = SQLiteApprovalStore(effective_session_db)
    audit_store = SQLiteAuditStore(effective_session_db)
    metrics = MetricsRegistry()

    app.state.firewall = firewall
    app.state.session_store = session_store
    app.state.approval_store = approval_store
    app.state.audit_store = audit_store
    app.state.metrics = metrics
    app.state.runtime_config = effective_runtime
    app.state.gateway_service = GatewayInspectionService(
        firewall=firewall,
        session_store=session_store,
        approval_store=approval_store,
        audit_store=audit_store,
    )

    limiter = DeterministicRateLimiter(
        requests_per_window=effective_runtime.rate_limit_requests,
        window_seconds=effective_runtime.rate_limit_window_seconds,
        now_fn=rate_limiter_now_fn,
    )
    app.add_middleware(
        GatewayGuardMiddleware,
        config=effective_runtime,
        metrics=metrics,
        rate_limiter=limiter,
        exempt_paths={"/health", "/ready"},
    )

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        app.state.audit_store.close()
        app.state.approval_store.close()
        app.state.session_store.close()

    @app.exception_handler(ValueError)
    async def handle_value_error(_: Request, exc: ValueError) -> JSONResponse:
        payload = _to_dict(ErrorResponse(error=str(exc), code="invalid_request", details=None))
        return JSONResponse(status_code=400, content=payload)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        payload = _to_dict(
            ErrorResponse(
                error="Request validation failed",
                code="validation_error",
                details={"errors": exc.errors()},
            )
        )
        return JSONResponse(status_code=422, content=payload)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        payload: Dict[str, Any] = _to_dict(
            ErrorResponse(
                error="Internal server error",
                code="internal_error",
                details={"type": exc.__class__.__name__},
            )
        )
        return JSONResponse(status_code=500, content=payload)

    app.include_router(health_router)
    app.include_router(inspect_router)
    app.include_router(approval_router)
    app.include_router(operator_router)
    return app


app = create_app()
