"""Structured logging, request correlation and Prometheus metrics (per-app registry, test-safe)."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    _RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        payload.update({k: v for k, v in record.__dict__.items() if k not in self._RESERVED})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def configure_logging(level: str = "INFO", as_json: bool = True) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        if getattr(handler, "_sentinel", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler._sentinel = True  # type: ignore[attr-defined]
    handler.setFormatter(JsonFormatter() if as_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"))
    handler.addFilter(_RequestIdFilter())
    root.addHandler(handler)
    logging.getLogger("uvicorn.access").disabled = True  # replaced by our structured access log


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter("sentinel_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=self.registry)
        self.http_latency = Histogram(
            "sentinel_http_request_duration_seconds",
            "HTTP latency",
            ["method", "route"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
        )
        self.investigations = Counter("sentinel_investigations_total", "Completed investigations", ["root_cause", "mode"], registry=self.registry)
        self.investigation_latency = Histogram(
            "sentinel_investigation_duration_seconds", "Investigation latency", registry=self.registry, buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 20)
        )
        self.remediation_decisions = Counter("sentinel_remediation_decisions_total", "Remediation decisions", ["decision"], registry=self.registry)
        self.llm_requests = Counter("sentinel_llm_requests_total", "Outbound LLM requests", ["outcome"], registry=self.registry)
        self.ingested = Counter("sentinel_ingested_incidents_total", "Incidents created via ingestion", ["source"], registry=self.registry)
