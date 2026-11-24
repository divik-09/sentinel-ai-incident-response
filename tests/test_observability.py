import json
import logging

from backend.app.observability import JsonFormatter, request_id_var
from tests.conftest import investigate_scenario


def test_metrics_endpoint_exposes_http_and_domain_counters(client):
    incident, result = investigate_scenario(client)
    rid = result.json()["remediation"]["id"]
    client.post(f"/api/incidents/{incident['id']}/remediations/{rid}/approve", json={})
    client.post(
        "/api/incidents/ingest",
        json={"title": "t", "service": "s", "summary": "x", "telemetry": [{"kind": "log", "service": "s", "payload": {"message": "m"}}]},
    )
    text = client.get("/metrics").text
    assert 'sentinel_http_requests_total{method="POST",route="/api/incidents/{incident_id}/investigate",status="200"} 1.0' in text
    assert 'sentinel_investigations_total{mode="deterministic",root_cause="database_connection_pool_exhaustion"} 1.0' in text
    assert 'sentinel_remediation_decisions_total{decision="approved"} 1.0' in text
    assert 'sentinel_ingested_incidents_total{source="api"} 1.0' in text
    assert "sentinel_http_request_duration_seconds_bucket" in text


def test_metrics_use_route_templates_not_raw_paths(client):
    client.get("/api/incidents/aaa")
    client.get("/api/incidents/bbb")
    text = client.get("/metrics").text
    assert 'route="/api/incidents/{incident_id}"' in text and "/api/incidents/aaa" not in text


def test_json_log_format_includes_request_id_and_extras():
    token = request_id_var.set("req-123")
    try:
        record = logging.LogRecord("sentinel.test", logging.INFO, __file__, 1, "hello %s", ("world",), None)
        record.status = 200
        payload = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert payload["msg"] == "hello world" and payload["request_id"] == "req-123" and payload["status"] == 200 and payload["level"] == "INFO"


def test_readiness_reports_schema_version(client):
    body = client.get("/api/ready").json()
    assert body == {"status": "ready", "schema_version": 4}
