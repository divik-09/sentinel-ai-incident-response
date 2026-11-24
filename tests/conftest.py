from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.config import ApiKeyEntry, Settings, hash_api_key
from backend.app.db import Database
from backend.app.main import create_app
from backend.app.scenarios import ScenarioRegistry
from backend.app.services.runbooks import RunbookRetriever

KEYS = {
    "viewer": "viewer-key-0000000000000001",
    "operator": "operator-key-00000000000001",
    "approver": "approver-key-00000000000001",
    "approver2": "approver-key-00000000000002",
}


def make_settings(**overrides) -> Settings:
    base = {"database_path": ":memory:", "log_level": "WARNING", "log_json": False, "rate_limit_per_minute": 0}
    base.update(overrides)
    return Settings(**base).validate()


def auth_settings(**overrides) -> Settings:
    entries = (
        ApiKeyEntry("vera", "viewer", hash_api_key(KEYS["viewer"])),
        ApiKeyEntry("olga", "operator", hash_api_key(KEYS["operator"])),
        ApiKeyEntry("alice", "approver", hash_api_key(KEYS["approver"])),
        ApiKeyEntry("bob", "approver", hash_api_key(KEYS["approver2"])),
    )
    return make_settings(auth_mode="api_key", api_keys=entries, **overrides)


def bearer(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {KEYS[role]}"}


@pytest.fixture
def db():
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def scenarios():
    return ScenarioRegistry()


@pytest.fixture
def runbooks():
    return RunbookRetriever()


@pytest.fixture
def make_client():
    clients: list[TestClient] = []

    def factory(settings: Settings | None = None, **kwargs) -> TestClient:
        client = TestClient(create_app(settings or make_settings(), **kwargs), raise_server_exceptions=False)
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(make_client) -> TestClient:
    """App with auth disabled (local-development mode)."""
    return make_client()


def investigate_scenario(client: TestClient, scenario_id: str = "payment-pool-exhaustion", headers: dict | None = None):
    headers = headers or {}
    incident = client.post("/api/incidents", json={"scenario_id": scenario_id}, headers=headers).json()
    result = client.post(f"/api/incidents/{incident['id']}/investigate", headers=headers)
    return incident, result
