"""Application factory. All state lives in a ``Services`` container attached to the app, so tests can
build isolated apps and nothing runs at import time."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .agent.llm_client import LLMClient
from .agent.llm_review import OptionalLLMReviewer
from .agent.llm_tool_agent import LLMToolCallingAgent
from .agent.runtime import InvestigationAgent
from .config import ROOT_DIR, Settings
from .db import LATEST_SCHEMA_VERSION, Database
from .errors import NotFoundError, SentinelError
from .models import DecisionRequest, EvaluationRequest, IncidentCreate, IngestRequest, OtlpIngestRequest
from .observability import Metrics, configure_logging, request_id_var
from .scenarios import ScenarioRegistry
from .security import Authenticator, BodyLimitMiddleware, Principal, SecurityHeadersMiddleware
from .services.demo_services import DemoServiceRuntime
from .services.evaluation import EvaluationService
from .services.incidents import IncidentService
from .services.otlp import otlp_to_telemetry
from .services.remediation import RemediationService
from .services.runbooks import RunbookRetriever

log = logging.getLogger("sentinel.api")
FRONTEND_DIR = ROOT_DIR / "frontend"


class OrderRequest(BaseModel):
    sku: str = Field(default="DEMO-001", min_length=1, max_length=80)
    quantity: int = Field(default=1, ge=1, le=100)
    amount: float = Field(default=999.0, gt=0, le=1_000_000)


class PaymentRequest(BaseModel):
    amount: float = Field(default=999.0, gt=0, le=1_000_000)
    currency: str = Field(default="INR", min_length=3, max_length=3)


class TokenRequest(BaseModel):
    subject: str = Field(default="demo-user", min_length=1, max_length=80)


@dataclass
class Services:
    settings: Settings
    db: Database
    scenarios: ScenarioRegistry
    runbooks: RunbookRetriever
    demo: DemoServiceRuntime
    incidents: IncidentService
    agent: InvestigationAgent
    remediations: RemediationService
    evaluations: EvaluationService
    auth: Authenticator
    metrics: Metrics
    llm_client: LLMClient | None = None


def build_services(settings: Settings, llm_transport: httpx.BaseTransport | None = None) -> Services:
    metrics = Metrics()
    db = Database(settings.database_path)
    scenarios = ScenarioRegistry()
    runbooks = RunbookRetriever()
    demo = DemoServiceRuntime()
    client: LLMClient | None = None
    if settings.openai_api_key and (settings.enable_llm_agent or settings.enable_model_synthesis):
        client = LLMClient(
            settings.openai_api_key,
            settings.openai_base_url,
            timeout=settings.llm_timeout_seconds,
            transport=llm_transport,
            on_event=lambda outcome: metrics.llm_requests.labels(outcome).inc(),
        )
    planner = LLMToolCallingAgent(client, settings.openai_model) if client and settings.enable_llm_agent else None
    reviewer = OptionalLLMReviewer(client, settings.openai_model) if client and settings.enable_model_synthesis else None

    def on_investigation(cause: str, seconds: float, mode: str) -> None:
        metrics.investigations.labels(cause, mode).inc()
        metrics.investigation_latency.observe(seconds)

    return Services(
        settings=settings,
        db=db,
        scenarios=scenarios,
        runbooks=runbooks,
        demo=demo,
        incidents=IncidentService(db, scenarios, demo),
        agent=InvestigationAgent(db, runbooks, reviewer, planner, on_complete=on_investigation),
        remediations=RemediationService(db, four_eyes=settings.four_eyes, on_decision=lambda d: metrics.remediation_decisions.labels(d).inc()),
        evaluations=EvaluationService(scenarios, runbooks),
        auth=Authenticator(settings),
        metrics=metrics,
        llm_client=client,
    )


def create_app(settings: Settings | None = None, *, llm_transport: httpx.BaseTransport | None = None) -> FastAPI:
    settings = (settings or Settings.from_env()).validate()
    configure_logging(settings.log_level, settings.log_json)
    svc = build_services(settings, llm_transport)
    if not settings.auth_enabled:
        log.warning("Authentication is DISABLED. Every request acts as 'local-operator' with approver rights. Never expose this instance.")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        log.info("sentinel starting", extra={"environment": settings.environment, "auth": settings.auth_mode, "schema_version": svc.db.schema_version()})
        yield
        if svc.llm_client:
            svc.llm_client.close()
        svc.db.close()

    app = FastAPI(
        title="Sentinel Incident Response API",
        description="Evidence-grounded incident triage with allowlisted tools, policy-gated sandbox remediation and a tamper-evident audit log.",
        version=settings.version,
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production_like else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not settings.is_production_like else None,
    )
    app.state.services = svc

    # Middleware order: last added runs first (outermost).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Request-ID"],
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production_like)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)

    @app.middleware("http")
    async def observe(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        rid = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            elapsed = time.perf_counter() - started
            route = getattr(request.scope.get("route"), "path", "unmatched")
            svc.metrics.http_requests.labels(request.method, route, str(status)).inc()
            svc.metrics.http_latency.labels(request.method, route).observe(elapsed)
            principal = getattr(request.state, "principal", None)
            if route not in {"/api/health", "/metrics"}:
                log.info(
                    f"{request.method} {request.url.path} -> {status} ({elapsed * 1000:.1f}ms)",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "route": route,
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 2),
                        "principal": principal.name if principal else None,
                    },
                )
            request_id_var.reset(token)

    # ------------------------------------------------------------------ errors
    @app.exception_handler(SentinelError)
    async def sentinel_error(_: Request, exc: SentinelError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message, "code": exc.code, **exc.extra})

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Request validation failed", "code": "validation_failed", "errors": errors})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"path": request.url.path})
        return JSONResponse(status_code=500, content={"detail": "Internal server error", "code": "internal_error", "request_id": request_id_var.get()})

    viewer, operator, approver = svc.auth.require("viewer"), svc.auth.require("operator"), svc.auth.require("approver")

    def demo_enabled() -> None:
        if not settings.enable_demo:
            raise HTTPException(404, "Demo features are disabled in this environment")

    # ------------------------------------------------------------------ public
    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/api/health", tags=["ops"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "sentinel-api", "version": settings.version, "environment": settings.environment}

    @app.get("/api/ready", tags=["ops"])
    def ready() -> JSONResponse:
        try:
            svc.db.ping()
            version = svc.db.schema_version()
            ok = version == LATEST_SCHEMA_VERSION
            return JSONResponse(status_code=200 if ok else 503, content={"status": "ready" if ok else "migrating", "schema_version": version})
        except Exception:
            return JSONResponse(status_code=503, content={"status": "unavailable"})

    @app.get("/api/config", tags=["ops"])
    def public_config() -> dict[str, Any]:
        return {
            "environment": settings.environment,
            "auth_mode": settings.auth_mode,
            "four_eyes": settings.four_eyes,
            "demo_enabled": settings.enable_demo,
            "llm_tool_agent_enabled": svc.agent.planner is not None,
            "model_review_enabled": svc.agent.reviewer is not None,
            "model": settings.openai_model if svc.llm_client else None,
            "execution_mode": "sandbox_simulation_only",
            "production_access": False,
            "version": settings.version,
        }

    @app.get("/metrics", include_in_schema=False)
    def metrics(_: Principal = Depends(viewer)) -> Response:
        return Response(generate_latest(svc.metrics.registry), media_type=CONTENT_TYPE_LATEST)

    @app.get("/api/me", tags=["auth"])
    def me(principal: Principal = Depends(viewer)) -> dict[str, str]:
        return {"name": principal.name, "role": principal.role}

    # --------------------------------------------------------------- incidents
    @app.get("/api/dashboard", tags=["incidents"])
    def dashboard_data(_: Principal = Depends(viewer)) -> dict[str, Any]:
        return {
            "counts": svc.db.dashboard_counts(),
            "incidents": svc.db.list_incidents(limit=12),
            "scenarios": svc.scenarios.public_all() if settings.enable_demo else [],
            "demo_services": svc.demo.statuses() if settings.enable_demo else [],
        }

    @app.get("/api/scenarios", tags=["incidents"])
    def list_scenarios(_: Principal = Depends(viewer)) -> list[dict[str, Any]]:
        return svc.scenarios.public_all() if settings.enable_demo else []

    @app.post("/api/incidents", status_code=201, tags=["incidents"])
    def create_incident(payload: IncidentCreate, principal: Principal = Depends(operator)) -> dict[str, Any]:
        demo_enabled()
        return svc.incidents.trigger(payload.scenario_id, actor=principal.name)

    @app.post("/api/incidents/ingest", status_code=201, tags=["ingestion"])
    def ingest(payload: IngestRequest, principal: Principal = Depends(operator)) -> JSONResponse:
        result = svc.incidents.ingest(payload, payload.telemetry, actor=principal.name, source="api")
        if not result["deduplicated"]:
            svc.metrics.ingested.labels("api").inc()
        return JSONResponse(status_code=200 if result["deduplicated"] else 201, content=result)

    @app.post("/api/incidents/ingest/otlp", status_code=201, tags=["ingestion"])
    def ingest_otlp(payload: OtlpIngestRequest, principal: Principal = Depends(operator)) -> JSONResponse:
        records = otlp_to_telemetry(payload.otlp, payload.deployments)
        result = svc.incidents.ingest(payload.incident, records, actor=principal.name, source="otlp")
        if not result["deduplicated"]:
            svc.metrics.ingested.labels("otlp").inc()
        return JSONResponse(status_code=200 if result["deduplicated"] else 201, content=result)

    @app.get("/api/incidents", tags=["incidents"])
    def list_incidents(limit: int = 50, offset: int = 0, status: str | None = None, _: Principal = Depends(viewer)) -> list[dict[str, Any]]:
        return svc.db.list_incidents(max(1, min(limit, 100)), max(0, offset), status)

    @app.get("/api/incidents/{incident_id}", tags=["incidents"])
    def get_incident(incident_id: str, _: Principal = Depends(viewer)) -> dict[str, Any]:
        incident = svc.db.get_incident(incident_id)
        if not incident:
            raise NotFoundError("Incident not found")
        return {
            "incident": incident,
            "telemetry": svc.db.get_telemetry(incident_id),
            "agent_run": svc.db.latest_agent_run(incident_id),
            "remediation": svc.db.latest_remediation(incident_id),
            "audit_events": svc.db.get_audit_events(incident_id),
        }

    @app.post("/api/incidents/{incident_id}/investigate", tags=["incidents"])
    def investigate(incident_id: str, principal: Principal = Depends(operator)) -> dict[str, Any]:
        return svc.agent.investigate(incident_id, actor=principal.name)

    # ------------------------------------------------------------ remediation
    @app.post("/api/incidents/{incident_id}/remediations/{remediation_id}/approve", tags=["remediation"])
    def approve(incident_id: str, remediation_id: str, payload: DecisionRequest, principal: Principal = Depends(approver)) -> dict[str, Any]:
        return svc.remediations.approve_and_execute(incident_id, remediation_id, principal.name, payload.note)

    @app.post("/api/incidents/{incident_id}/remediations/{remediation_id}/reject", tags=["remediation"])
    def reject(incident_id: str, remediation_id: str, payload: DecisionRequest, principal: Principal = Depends(approver)) -> dict[str, Any]:
        return svc.remediations.reject(incident_id, remediation_id, principal.name, payload.note)

    @app.post("/api/incidents/{incident_id}/remediations/{remediation_id}/rollback", tags=["remediation"])
    def rollback(incident_id: str, remediation_id: str, payload: DecisionRequest, principal: Principal = Depends(approver)) -> dict[str, Any]:
        return svc.remediations.rollback(incident_id, remediation_id, principal.name, payload.note)

    # ------------------------------------------------------------ audit / eval
    @app.get("/api/audit/verify", tags=["audit"])
    def verify_audit(_: Principal = Depends(viewer)) -> dict[str, Any]:
        return svc.db.verify_audit_chain()

    @app.post("/api/evaluations/run", tags=["evaluation"])
    def run_evaluation(payload: EvaluationRequest | None = None, _: Principal = Depends(operator)) -> dict[str, Any]:
        return svc.evaluations.run((payload or EvaluationRequest()).split)

    @app.get("/api/runbooks", tags=["incidents"])
    def list_runbooks(_: Principal = Depends(viewer)) -> list[dict[str, Any]]:
        return svc.runbooks.runbooks

    # ------------------------------------------------------------------- demo
    @app.get("/api/demo/services", tags=["demo"])
    def demo_service_status(_: Principal = Depends(viewer)) -> dict[str, Any]:
        demo_enabled()
        return {"mode": "in_process_simulator", "note": "Local demo handlers, not production services.", "services": svc.demo.statuses()}

    @app.post("/api/demo/reset", tags=["demo"])
    def reset_demo_services(_: Principal = Depends(operator)) -> dict[str, Any]:
        demo_enabled()
        svc.demo.reset()
        return {"status": "reset", "services": svc.demo.statuses()}

    @app.post("/api/demo/services/{service}/reset", tags=["demo"])
    def reset_demo_service(service: str, _: Principal = Depends(operator)) -> dict[str, Any]:
        demo_enabled()
        try:
            svc.demo.reset(service)
        except KeyError as exc:
            raise NotFoundError(str(exc.args[0])) from exc
        return {"status": "reset", "services": svc.demo.statuses()}

    @app.post("/demo/payments/authorize", tags=["demo"])
    def demo_payment_authorize(payload: PaymentRequest, _: Principal = Depends(operator)) -> JSONResponse:
        demo_enabled()
        status, result = svc.demo.authorize_payment(payload.amount, payload.currency)
        return JSONResponse(status_code=status, content=result)

    @app.get("/demo/inventory/stock/{sku}", tags=["demo"])
    def demo_inventory_stock(sku: str, quantity: int = 1, _: Principal = Depends(operator)) -> JSONResponse:
        demo_enabled()
        if not 1 <= quantity <= 100:
            raise HTTPException(422, "quantity must be between 1 and 100")
        status, result = svc.demo.lookup_inventory(sku[:80], quantity)
        return JSONResponse(status_code=status, content=result)

    @app.post("/demo/orders", tags=["demo"])
    def demo_place_order(payload: OrderRequest, _: Principal = Depends(operator)) -> JSONResponse:
        demo_enabled()
        status, result = svc.demo.place_order(payload.sku, payload.quantity, payload.amount)
        return JSONResponse(status_code=status, content=result)

    @app.get("/demo/catalog/products", tags=["demo"])
    def demo_catalog_products(_: Principal = Depends(operator)) -> JSONResponse:
        demo_enabled()
        status, result = svc.demo.list_products()
        return JSONResponse(status_code=status, content=result)

    @app.post("/demo/auth/token", tags=["demo"])
    def demo_auth_token(payload: TokenRequest, _: Principal = Depends(operator)) -> JSONResponse:
        demo_enabled()
        status, result = svc.demo.issue_token(payload.subject)
        return JSONResponse(status_code=status, content=result)

    return app
