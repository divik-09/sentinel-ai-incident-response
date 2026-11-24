import json

from tests.conftest import auth_settings, bearer


def payload(**overrides):
    base = {
        "external_id": "alert-1042",
        "title": "Ledger writes stalling",
        "service": "ledger",
        "severity": "high",
        "summary": "writes failing",
        "telemetry": [
            {"kind": "metric", "service": "ledger", "payload": {"name": "db_pool_utilization", "value": 0.99, "unit": "ratio", "threshold": 0.85}},
            {
                "kind": "log",
                "service": "ledger",
                "payload": {"level": "ERROR", "code": "DB_POOL_TIMEOUT", "message": "Timed out waiting to acquire a database connection"},
            },
            {"kind": "trace", "service": "ledger", "payload": {"operation": "db.acquire_connection", "duration_ms": 2100, "status": "ERROR", "attributes": {}}},
        ],
    }
    base.update(overrides)
    return base


def test_ingest_investigate_and_cite_end_to_end(client):
    created = client.post("/api/incidents/ingest", json=payload())
    assert created.status_code == 201 and created.json()["telemetry_count"] == 3
    result = client.post(f"/api/incidents/{created.json()['id']}/investigate").json()
    assert result["incident"]["root_cause"] == "database_connection_pool_exhaustion"
    assert result["incident"]["diagnosis"]["evidence_count"] == 3


def test_ingest_is_idempotent_on_external_id(client):
    first = client.post("/api/incidents/ingest", json=payload()).json()
    again = client.post("/api/incidents/ingest", json=payload())
    assert again.status_code == 200 and again.json()["id"] == first["id"] and again.json()["deduplicated"] is True
    assert len(client.get("/api/incidents").json()) == 1


def test_secrets_are_redacted_before_they_are_stored(client):
    body = payload(external_id="s1")
    body["telemetry"][1]["payload"]["message"] = "timeout for dave@corp.io Authorization: Bearer abcdef1234567890ZZZ card 4111-1111-1111-1111"
    created = client.post("/api/incidents/ingest", json=body).json()
    assert created["redaction"]["redactions"]
    stored = json.dumps(client.get(f"/api/incidents/{created['id']}").json())
    for leaked in ("dave@corp.io", "abcdef1234567890ZZZ", "4111-1111-1111-1111"):
        assert leaked not in stored
    audit = client.get(f"/api/incidents/{created['id']}").json()["audit_events"][0]
    assert audit["details"]["redactions"]  # redaction counts are audited, values are not


def test_ingest_validation(client):
    assert client.post("/api/incidents/ingest", json=payload(telemetry=[])).status_code == 422
    assert client.post("/api/incidents/ingest", json=payload(external_id="has spaces!")).status_code == 422
    bad_kind = payload()
    bad_kind["telemetry"][0]["kind"] = "profile"
    assert client.post("/api/incidents/ingest", json=bad_kind).status_code == 422
    huge = payload()
    huge["telemetry"][0]["payload"]["blob"] = "x" * 20_000
    assert client.post("/api/incidents/ingest", json=huge).status_code == 422
    bad_ts = payload()
    bad_ts["telemetry"][0]["timestamp"] = "yesterday"
    assert client.post("/api/incidents/ingest", json=bad_ts).status_code == 422
    too_many = payload(telemetry=[payload()["telemetry"][0]] * 501)
    assert client.post("/api/incidents/ingest", json=too_many).status_code == 422
    assert client.post("/api/incidents/ingest", json={**payload(), "unexpected": 1}).status_code == 422


def test_ingest_requires_operator_role(make_client):
    client = make_client(auth_settings())
    assert client.post("/api/incidents/ingest", json=payload(), headers=bearer("viewer")).status_code == 403
    assert client.post("/api/incidents/ingest", json=payload(), headers=bearer("operator")).status_code == 201


# ------------------------------------------------------------------------------ OTLP
def _attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def otlp_pool_exhaustion():
    resource = {"attributes": [_attr("service.name", "ledger")]}
    now = 1_760_000_000_000_000_000
    return {
        "resourceMetrics": [
            {
                "resource": resource,
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "db.pool.utilization",
                                "unit": "1",
                                "gauge": {"dataPoints": [{"timeUnixNano": str(now - 10), "asDouble": 0.4}, {"timeUnixNano": str(now), "asDouble": 0.99}]},
                            }
                        ]
                    }
                ],
            }
        ],
        "resourceLogs": [
            {
                "resource": resource,
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": str(now),
                                "severityText": "error",
                                "body": {"stringValue": "Timed out waiting to acquire a database connection"},
                                "attributes": [_attr("code", "DB_POOL_TIMEOUT")],
                            }
                        ]
                    }
                ],
            }
        ],
        "resourceSpans": [
            {
                "resource": resource,
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "t1",
                                "spanId": "s1",
                                "name": "db.acquire_connection",
                                "startTimeUnixNano": str(now),
                                "endTimeUnixNano": str(now + 2_100_000_000),
                                "status": {"code": 2},
                                "attributes": [_attr("db.system", "postgresql")],
                            }
                        ]
                    }
                ],
            }
        ],
    }


def test_otlp_json_adapter_end_to_end(client):
    body = {
        "incident": {"title": "OTLP pool exhaustion", "service": "ledger", "severity": "critical", "summary": "from otlp", "external_id": "otlp-1"},
        "otlp": otlp_pool_exhaustion(),
        "deployments": [{"service": "ledger", "version": "ledger-1.2.3", "changes": "Reduced pool size from 20 to 4"}],
    }
    created = client.post("/api/incidents/ingest/otlp", json=body)
    assert created.status_code == 201 and created.json()["telemetry_count"] == 4
    result = client.post(f"/api/incidents/{created.json()['id']}/investigate").json()
    diagnosis = result["incident"]["diagnosis"]
    assert result["incident"]["root_cause"] == "database_connection_pool_exhaustion"
    assert diagnosis["evidence_count"] == 4  # metric (latest data point 0.99, unit "1" -> ratio), log, 2.1s ERROR span, deployment


def test_otlp_without_supported_data_is_rejected(client):
    body = {"incident": {"title": "t", "service": "s", "summary": "x"}, "otlp": {"resourceSpans": []}}
    response = client.post("/api/incidents/ingest/otlp", json=body)
    assert response.status_code == 422 and "no supported" in response.json()["detail"]


def test_otlp_tolerates_malformed_points(client):
    otlp = otlp_pool_exhaustion()
    otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"].append({"name": "broken", "gauge": {"dataPoints": [{"timeUnixNano": "abc"}]}})
    otlp["resourceSpans"][0]["scopeSpans"][0]["spans"].append({"name": "no-times"})
    body = {"incident": {"title": "t", "service": "ledger", "summary": "x"}, "otlp": otlp}
    assert client.post("/api/incidents/ingest/otlp", json=body).status_code == 201
