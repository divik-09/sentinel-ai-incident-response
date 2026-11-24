from tests.conftest import investigate_scenario


def test_full_lifecycle_over_http_with_verified_audit_chain(client):
    incident, result = investigate_scenario(client, "inventory-dependency-latency")
    body = result.json()
    assert result.status_code == 200 and body["incident"]["root_cause"] == "downstream_dependency_latency"
    assert body["incident"]["status"] == "awaiting_approval" and body["remediation"]["proposal"]["policy"]["allowed"] is True
    rid = body["remediation"]["id"]

    approved = client.post(f"/api/incidents/{incident['id']}/remediations/{rid}/approve", json={"note": "lgtm"})
    assert approved.status_code == 200 and approved.json()["status"] == "executed_in_sandbox"
    detail = client.get(f"/api/incidents/{incident['id']}").json()
    assert detail["incident"]["status"] == "simulated"
    assert [e["action"] for e in detail["audit_events"]] == ["incident.detected", "investigation.completed", "remediation.approved_and_simulated"]

    rolled = client.post(f"/api/incidents/{incident['id']}/remediations/{rid}/rollback", json={})
    assert rolled.status_code == 200 and rolled.json()["status"] == "rolled_back"
    verify = client.get("/api/audit/verify").json()
    assert verify["valid"] and verify["checked"] == 4


def test_conflicts_and_not_found_have_correct_status_codes(client):
    incident, result = investigate_scenario(client)
    rid = result.json()["remediation"]["id"]
    base = f"/api/incidents/{incident['id']}/remediations/{rid}"
    assert client.post(f"{base}/approve", json={}).status_code == 200
    assert client.post(f"{base}/approve", json={}).status_code == 409
    assert client.post(f"{base}/reject", json={}).status_code == 409
    assert client.post(f"/api/incidents/{incident['id']}/investigate").status_code == 409
    assert client.get("/api/incidents/nope").status_code == 404
    assert client.post("/api/incidents/nope/investigate").status_code == 404
    assert client.post(f"/api/incidents/{incident['id']}/remediations/nope/approve", json={}).status_code == 404


def test_list_pagination_and_status_filter(client):
    for scenario in ("payment-pool-exhaustion", "orders-schema-mismatch", "catalog-cache-stampede"):
        client.post("/api/incidents", json={"scenario_id": scenario})
    assert len(client.get("/api/incidents?limit=2").json()) == 2
    assert len(client.get("/api/incidents?limit=2&offset=2").json()) == 1
    assert len(client.get("/api/incidents?status=detected").json()) == 3 and client.get("/api/incidents?status=simulated").json() == []
    assert len(client.get("/api/incidents?limit=9999").json()) == 3  # clamped, not an error


def test_dashboard_counts_and_demo_services(client):
    client.post("/api/incidents", json={"scenario_id": "payment-pool-exhaustion"})
    data = client.get("/api/dashboard").json()
    assert data["counts"]["total_incidents"] == 1 and data["counts"]["critical_open"] == 1 and len(data["scenarios"]) == 5
    assert any(s["status"] == "degraded" for s in data["demo_services"])
    assert client.post("/demo/orders", json={}).status_code == 503  # injected payments fault propagates
    client.post("/api/demo/reset")
    assert client.post("/demo/orders", json={}).status_code == 201
    assert client.post("/api/demo/services/nope/reset").status_code == 404
    assert client.get("/demo/inventory/stock/X?quantity=0").status_code == 422


def test_unknown_diagnosis_over_http_proposes_manual_investigation_only(client):
    created = client.post(
        "/api/incidents/ingest",
        json={
            "title": "mystery",
            "service": "x",
            "summary": "?",
            "telemetry": [{"kind": "log", "service": "x", "payload": {"level": "ERROR", "code": "WEIRD", "message": "something odd"}}],
        },
    ).json()
    result = client.post(f"/api/incidents/{created['id']}/investigate").json()
    assert result["incident"]["root_cause"] == "unknown" and result["incident"]["status"] == "diagnosed"
    proposal = result["remediation"]["proposal"]
    assert proposal["action"] == "manual_investigation_required" and proposal["missing_evidence"]
    assert client.post(f"/api/incidents/{created['id']}/remediations/{result['remediation']['id']}/approve", json={}).status_code == 409


def test_runbooks_and_config(client):
    assert len(client.get("/api/runbooks").json()) == 5
    config = client.get("/api/config").json()
    assert config["execution_mode"] == "sandbox_simulation_only" and config["production_access"] is False
    assert config["llm_tool_agent_enabled"] is False
