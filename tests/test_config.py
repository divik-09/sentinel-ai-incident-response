import pytest

from backend.app.config import ApiKeyEntry, ConfigError, Settings, hash_api_key, parse_api_keys


def test_parse_api_keys_roundtrip():
    digest = hash_api_key("secret")
    entries = parse_api_keys(f"alice:approver:{digest}, bob:viewer:{digest}")
    assert [(e.name, e.role) for e in entries] == [("alice", "approver"), ("bob", "viewer")]


@pytest.mark.parametrize("raw", ["alice:approver", "alice:root:" + "a" * 64, "alice:viewer:nothex", f"a:viewer:{'a' * 64},a:viewer:{'a' * 64}"])
def test_parse_api_keys_rejects_malformed_entries(raw):
    with pytest.raises(ConfigError):
        parse_api_keys(raw)


def test_production_refuses_to_start_without_auth():
    with pytest.raises(ConfigError, match="without authentication"):
        Settings(environment="production").validate()


def test_production_rejects_wildcard_cors():
    entry = ApiKeyEntry("a", "viewer", hash_api_key("k"))
    with pytest.raises(ConfigError, match="CORS"):
        Settings(environment="production", auth_mode="api_key", api_keys=(entry,), cors_origins=("*",)).validate()


def test_api_key_mode_requires_keys():
    with pytest.raises(ConfigError):
        Settings(auth_mode="api_key").validate()


def test_llm_agent_requires_key():
    with pytest.raises(ConfigError):
        Settings(enable_llm_agent=True).validate()


def test_from_env_is_secure_by_default_when_keys_present(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("SENTINEL_API_KEYS", f"ops:approver:{hash_api_key('k')}")
    monkeypatch.delenv("SENTINEL_AUTH_MODE", raising=False)
    settings = Settings.from_env()
    assert settings.auth_enabled and settings.four_eyes and not settings.enable_demo
