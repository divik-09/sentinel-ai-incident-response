import json

import pytest

from backend.app.config import ApiKeyEntry, Settings, hash_api_key
from tests.conftest import KEYS, auth_settings, bearer, investigate_scenario, make_settings


@pytest.fixture
def secured(make_client):
    return make_client(auth_settings())


def test_every_data_endpoint_requires_authentication(secured):
    for method, path in [
        ("GET", "/api/dashboard"),
        ("GET", "/api/incidents"),
        ("GET", "/api/runbooks"),
        ("GET", "/api/audit/verify"),
        ("GET", "/api/me"),
        ("GET", "/metrics"),
        ("POST", "/api/incidents"),
        ("POST", "/api/evaluations/run"),
        ("POST", "/demo/orders"),
    ]:
        response = secured.request(method, path, json={} if method == "POST" else None)
        assert response.status_code == 401, (method, path)
        assert response.headers["www-authenticate"] == "Bearer"


def test_public_endpoints_stay_public_and_leak_nothing_sensitive(secured):
    assert secured.get("/api/health").status_code == 200
    assert secured.get("/api/ready").json()["status"] == "ready"
    config = secured.get("/api/config").json()
    assert config["auth_mode"] == "api_key" and "api_keys" not in json.dumps(config)
    assert secured.get("/").status_code == 200


def test_wrong_and_malformed_keys_are_rejected(secured):
    assert secured.get("/api/me", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert secured.get("/api/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert secured.get("/api/me", headers={"X-API-Key": KEYS["viewer"]}).json() == {"name": "vera", "role": "viewer"}


def test_repeated_failed_authentication_is_throttled(secured):
    codes = [secured.get("/api/me", headers={"Authorization": "Bearer wrong"}).status_code for _ in range(14)]
    assert codes[:10] == [401] * 10 and 429 in codes[10:]
    throttled = secured.get("/api/me", headers={"Authorization": "Bearer wrong"})
    assert throttled.status_code == 429 and "retry-after" in throttled.headers


def test_roles_are_enforced(secured):
    # viewer can read but not act
    assert secured.get("/api/incidents", headers=bearer("viewer")).status_code == 200
    assert secured.post("/api/incidents", json={"scenario_id": "payment-pool-exhaustion"}, headers=bearer("viewer")).status_code == 403
    # operator can create/investigate but not decide
    incident, result = investigate_scenario(secured, headers=bearer("operator"))
    assert result.status_code == 200
    rid = result.json()["remediation"]["id"]
    for verb in ("approve", "reject", "rollback"):
        assert secured.post(f"/api/incidents/{incident['id']}/remediations/{rid}/{verb}", json={}, headers=bearer("operator")).status_code == 403
    # approver can
    assert secured.post(f"/api/incidents/{incident['id']}/remediations/{rid}/approve", json={}, headers=bearer("approver")).status_code == 200


def test_actor_in_audit_trail_comes_from_the_credential_not_the_request_body(secured):
    incident, result = investigate_scenario(secured, headers=bearer("operator"))
    rid = result.json()["remediation"]["id"]
    secured.post(f"/api/incidents/{incident['id']}/remediations/{rid}/approve", json={"note": "ok", "approved_by": "the-ceo"}, headers=bearer("approver"))
    detail = secured.get(f"/api/incidents/{incident['id']}", headers=bearer("viewer")).json()
    actors = [(e["action"], e["actor"]) for e in detail["audit_events"]]
    assert ("incident.detected", "olga") in actors and ("investigation.completed", "olga") in actors
    assert ("remediation.approved_and_simulated", "alice") in actors
    assert detail["remediation"]["approved_by"] == "alice" and "the-ceo" not in json.dumps(detail)


def test_four_eyes_over_http(make_client):
    client = make_client(auth_settings(four_eyes=True))
    incident = client.post("/api/incidents", json={"scenario_id": "payment-pool-exhaustion"}, headers=bearer("approver")).json()  # alice creates
    rid = client.post(f"/api/incidents/{incident['id']}/investigate", headers=bearer("operator")).json()["remediation"]["id"]
    url = f"/api/incidents/{incident['id']}/remediations/{rid}/approve"
    assert client.post(url, json={}, headers=bearer("approver")).status_code == 403  # alice created it
    assert client.post(url, json={}, headers={"Authorization": f"Bearer {KEYS['approver2']}"}).status_code == 200  # bob may approve


def test_request_body_limit_returns_413(make_client):
    client = make_client(make_settings(max_body_bytes=2048))
    response = client.post("/api/incidents", content=b"x" * 5000, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_rate_limit_returns_429_with_retry_after(make_client):
    client = make_client(auth_settings(rate_limit_per_minute=5))
    codes = [client.get("/api/me", headers=bearer("viewer")).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and set(codes[5:]) == {429}
    assert "retry-after" in client.get("/api/me", headers=bearer("viewer")).headers


def test_security_headers_present_on_app_and_api_responses(client):
    for path in ("/", "/api/health"):
        headers = client.get(path).headers
        assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in headers["content-security-policy"] and headers["referrer-policy"] == "no-referrer"
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_request_id_is_generated_and_propagated(client):
    assert len(client.get("/api/health").headers["x-request-id"]) >= 8
    assert client.get("/api/health", headers={"X-Request-ID": "trace-me-123"}).headers["x-request-id"] == "trace-me-123"


def test_unexpected_errors_do_not_leak_internals(make_client, monkeypatch):
    client = make_client()
    monkeypatch.setattr(client.app.state.services.db, "dashboard_counts", lambda: (_ for _ in ()).throw(RuntimeError("secret-internal-detail")))
    response = client.get("/api/dashboard")
    assert response.status_code == 500 and "secret-internal-detail" not in response.text and response.json()["code"] == "internal_error"


def test_validation_errors_are_structured_and_unknown_fields_rejected(client):
    response = client.post("/api/incidents", json={"scenario_id": "x", "evil": 1})
    assert response.status_code == 422 and response.json()["code"] == "validation_failed"
    assert client.post("/api/incidents", json={"scenario_id": "does-not-exist"}).status_code == 404


def test_production_like_config_hides_docs_and_demo_endpoints(make_client):
    entry = ApiKeyEntry("ops", "approver", hash_api_key("k" * 24))
    client = make_client(
        Settings(
            environment="production",
            database_path=":memory:",
            auth_mode="api_key",
            api_keys=(entry,),
            log_level="WARNING",
            log_json=False,
            rate_limit_per_minute=0,
            enable_demo=False,
        )
    )
    headers = {"Authorization": f"Bearer {'k' * 24}"}
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404
    assert client.get("/api/scenarios", headers=headers).json() == []
    assert client.post("/api/incidents", json={"scenario_id": "payment-pool-exhaustion"}, headers=headers).status_code == 404
    assert client.post("/demo/orders", json={}, headers=headers).status_code == 404
    assert "strict-transport-security" in client.get("/api/health").headers


def test_auth_disabled_mode_is_visible_in_config(client):
    assert client.get("/api/config").json()["auth_mode"] == "disabled"
    assert client.get("/api/me").json()["name"] == "local-operator"
