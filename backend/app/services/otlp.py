"""Adapter from an OTLP/JSON export (subset) to Sentinel's normalised telemetry records.

Supported: ``resourceSpans``, ``resourceLogs``, ``resourceMetrics`` (gauge and sum data points).
Not supported: OTLP/gRPC or protobuf transport, histograms/exponential histograms, exemplars.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

from ..errors import ValidationFailed
from ..models import MAX_TELEMETRY_RECORDS, DeploymentIn

_UNIT_MAP = {"1": "ratio", "%": "percent", "ms": "ms", "s": "s", "By": "bytes", "us": "us"}


def _attrs(items: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in _dicts(items):
        raw_value = item.get("value")
        value: dict[str, Any] = raw_value if isinstance(raw_value, dict) else {}
        for kind in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if kind in value:
                v = value[kind]
                with contextlib.suppress(TypeError, ValueError):
                    out[str(item.get("key"))] = int(v) if kind == "intValue" else v
                break
    return out


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dicts(items: Any) -> list[dict[str, Any]]:
    """OTLP input is untrusted: ignore anything that is not a list of objects instead of crashing."""
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _nano(point: dict[str, Any]) -> int:
    try:
        return int(point.get("timeUnixNano") or 0)
    except (TypeError, ValueError):
        return 0


def _iso(nanos: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(nanos) / 1e9, tz=UTC).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _service(resource: Any) -> str:
    attrs = resource.get("attributes") if isinstance(resource, dict) else None
    return str(_attrs(attrs).get("service.name", "unknown"))[:80]


def otlp_to_telemetry(body: dict[str, Any], deployments: list[DeploymentIn] | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for rs in _dicts(body.get("resourceSpans")):
        service = _service(rs.get("resource"))
        for ss in _dicts(rs.get("scopeSpans")):
            for span in _dicts(ss.get("spans")):
                start, end = span.get("startTimeUnixNano"), span.get("endTimeUnixNano")
                start_ns, end_ns = _to_int(start), _to_int(end)
                duration_ms = round((end_ns - start_ns) / 1e6, 3) if start_ns is not None and end_ns is not None else 0.0
                status = span.get("status")
                code = status.get("code") if isinstance(status, dict) else None
                is_error = code in (2, "STATUS_CODE_ERROR", "ERROR")
                payload = {
                    "trace_id": span.get("traceId"),
                    "span_id": span.get("spanId"),
                    "parent_span_id": span.get("parentSpanId") or None,
                    "operation": span.get("name", ""),
                    "duration_ms": duration_ms,
                    "status": "ERROR" if is_error else "OK",
                    "attributes": _attrs(span.get("attributes")),
                }
                records.append({"kind": "trace", "service": service, "timestamp": _iso(start), "payload": payload})

    for rl in _dicts(body.get("resourceLogs")):
        service = _service(rl.get("resource"))
        for sl in _dicts(rl.get("scopeLogs")):
            for log in _dicts(sl.get("logRecords")):
                attrs = _attrs(log.get("attributes"))
                body_value = log.get("body")
                message = str(body_value.get("stringValue", "")) if isinstance(body_value, dict) else ""
                code = attrs.get("code") or attrs.get("error.code") or attrs.get("event.name") or attrs.get("exception.type") or ""
                payload = {
                    "level": str(log.get("severityText", "INFO")).upper(),
                    "code": str(code),
                    "message": message,
                    "request_id": attrs.get("request.id") or attrs.get("request_id"),
                    "trace_id": log.get("traceId"),
                }
                records.append({"kind": "log", "service": service, "timestamp": _iso(log.get("timeUnixNano")), "payload": payload})

    for rm in _dicts(body.get("resourceMetrics")):
        service = _service(rm.get("resource"))
        for sm in _dicts(rm.get("scopeMetrics")):
            for metric in _dicts(sm.get("metrics")):
                data = metric.get("gauge") or metric.get("sum") or {}
                points = _dicts(data.get("dataPoints")) if isinstance(data, dict) else []
                if not points:
                    continue
                point = max(points, key=_nano)
                value = _to_float(point.get("asDouble", point.get("asInt")))
                if value is None or value != value or value in (float("inf"), float("-inf")):  # NaN / inf cannot be reasoned about
                    continue
                unit = _UNIT_MAP.get(str(metric.get("unit", "")), str(metric.get("unit", "")) or None)
                metric_payload: dict[str, Any] = {"name": str(metric.get("name", "")), "value": value, "unit": unit}
                metric_payload.update({k: v for k, v in _attrs(point.get("attributes")).items() if k in {"limit", "threshold"}})
                records.append({"kind": "metric", "service": service, "timestamp": _iso(point.get("timeUnixNano")), "payload": metric_payload})

    for dep in deployments or []:
        records.append(
            {
                "kind": "deployment",
                "service": dep.service,
                "timestamp": dep.deployed_at,
                "payload": {"version": dep.version, "commit": dep.commit, "changes": dep.changes, "deployed_at": dep.deployed_at},
            }
        )

    if not records:
        raise ValidationFailed("OTLP payload contained no supported spans, log records or metric data points")
    if len(records) > MAX_TELEMETRY_RECORDS:
        raise ValidationFailed(f"OTLP payload produced {len(records)} records; the limit is {MAX_TELEMETRY_RECORDS}")
    return records
