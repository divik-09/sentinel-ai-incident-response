"""Typed, validated application settings.

Settings are read once from the environment (``Settings.from_env``) and passed
explicitly into ``create_app``. Nothing at import time touches the filesystem
or network, which keeps tests hermetic and the app factory pure.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(__file__).resolve().parent / "data"

ROLES = ("viewer", "operator", "approver")
PRODUCTION_LIKE_ENVS = {"production", "staging"}


class ConfigError(ValueError):
    """Raised at startup when configuration is unsafe or inconsistent."""


@dataclass(frozen=True)
class ApiKeyEntry:
    """A named credential. Only the SHA-256 digest of the key is ever stored."""

    name: str
    role: str
    sha256: str

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ConfigError(f"Unknown role '{self.role}' for API key '{self.name}'. Valid roles: {', '.join(ROLES)}")
        if len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256):
            raise ConfigError(f"API key '{self.name}' must be configured with a 64-char lowercase SHA-256 hex digest")


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def parse_api_keys(raw: str) -> tuple[ApiKeyEntry, ...]:
    """Parse ``name:role:sha256`` entries separated by commas."""
    entries: list[ApiKeyEntry] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":")
        if len(parts) != 3:
            raise ConfigError("SENTINEL_API_KEYS entries must look like 'name:role:sha256hex'")
        entries.append(ApiKeyEntry(name=parts[0].strip(), role=parts[1].strip().lower(), sha256=parts[2].strip().lower()))
    names = [e.name for e in entries]
    if len(names) != len(set(names)):
        raise ConfigError("SENTINEL_API_KEYS contains duplicate key names")
    return tuple(entries)


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


@dataclass(frozen=True)
class Settings:
    app_name: str = "Sentinel"
    version: str = "2.0.0"
    environment: str = "development"
    database_path: str = str(ROOT_DIR / "sentinel.db")

    # Security
    auth_mode: str = "disabled"  # "api_key" | "disabled"
    api_keys: tuple[ApiKeyEntry, ...] = field(default_factory=tuple)
    four_eyes: bool = False  # the approver must differ from whoever created/investigated the incident
    rate_limit_per_minute: int = 240  # 0 disables
    max_body_bytes: int = 1_048_576
    cors_origins: tuple[str, ...] = ("http://localhost:8000",)
    enable_demo: bool = True  # demo fault-injection endpoints and scenario launcher

    # Observability
    log_level: str = "INFO"
    log_json: bool = True

    # Optional LLM integrations (off by default)
    openai_api_key: str | None = None
    openai_model: str = "gpt-4.1-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    enable_llm_agent: bool = False
    enable_model_synthesis: bool = False
    llm_timeout_seconds: float = 18.0

    @property
    def is_production_like(self) -> bool:
        return self.environment in PRODUCTION_LIKE_ENVS

    @property
    def auth_enabled(self) -> bool:
        return self.auth_mode == "api_key"

    def with_overrides(self, **changes: object) -> Settings:
        return replace(self, **changes)  # type: ignore[arg-type]

    def validate(self) -> Settings:
        if self.auth_mode not in {"api_key", "disabled"}:
            raise ConfigError("SENTINEL_AUTH_MODE must be 'api_key' or 'disabled'")
        if self.auth_enabled and not self.api_keys:
            raise ConfigError("SENTINEL_AUTH_MODE=api_key requires at least one entry in SENTINEL_API_KEYS")
        if self.is_production_like:
            if not self.auth_enabled:
                raise ConfigError(f"Refusing to start in '{self.environment}' without authentication. Set SENTINEL_API_KEYS.")
            if "*" in self.cors_origins:
                raise ConfigError("Wildcard CORS origins are not allowed in production-like environments")
        if self.enable_llm_agent and not self.openai_api_key:
            raise ConfigError("SENTINEL_ENABLE_LLM_AGENT=true requires OPENAI_API_KEY")
        if self.rate_limit_per_minute < 0 or self.max_body_bytes < 1024:
            raise ConfigError("Invalid rate limit or body size configuration")
        return self

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        environment = os.getenv("SENTINEL_ENV", "development").strip().lower()
        production_like = environment in PRODUCTION_LIKE_ENVS
        api_keys = parse_api_keys(os.getenv("SENTINEL_API_KEYS", ""))
        # Secure by default: if keys exist, auth is on. It can only be disabled explicitly,
        # and production-like environments refuse to start with it off.
        default_mode = "api_key" if api_keys else "disabled"
        cors = tuple(o.strip() for o in os.getenv("SENTINEL_CORS_ORIGINS", "http://localhost:8000").split(",") if o.strip())
        return cls(
            environment=environment,
            database_path=os.getenv("SENTINEL_DATABASE_PATH", str(ROOT_DIR / "sentinel.db")),
            auth_mode=os.getenv("SENTINEL_AUTH_MODE", default_mode).strip().lower(),
            api_keys=api_keys,
            four_eyes=_bool("SENTINEL_FOUR_EYES", production_like),
            rate_limit_per_minute=_int("SENTINEL_RATE_LIMIT_PER_MINUTE", 240),
            max_body_bytes=_int("SENTINEL_MAX_BODY_BYTES", 1_048_576, minimum=1024),
            cors_origins=cors or ("http://localhost:8000",),
            enable_demo=_bool("SENTINEL_ENABLE_DEMO", not production_like),
            log_level=os.getenv("SENTINEL_LOG_LEVEL", "INFO").upper(),
            log_json=_bool("SENTINEL_LOG_JSON", True),
            openai_api_key=os.getenv("OPENAI_API_KEY") or None,
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            openai_base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            enable_llm_agent=_bool("SENTINEL_ENABLE_LLM_AGENT", False),
            enable_model_synthesis=_bool("SENTINEL_ENABLE_MODEL_SYNTHESIS", False),
            llm_timeout_seconds=float(os.getenv("SENTINEL_LLM_TIMEOUT_SECONDS", "18")),
        ).validate()
