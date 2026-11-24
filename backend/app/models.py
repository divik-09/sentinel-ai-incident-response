from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PAYLOAD_BYTES = 8 * 1024
MAX_TELEMETRY_RECORDS = 500
_EXTERNAL_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


Severity = Literal["critical", "high", "medium", "low"]
TelemetryKind = Literal["metric", "log", "trace", "deployment"]


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(min_length=1, max_length=80)


class IncidentMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_id: str | None = Field(default=None, description="Idempotency key; re-posting the same id returns the existing incident.")
    title: str = Field(min_length=1, max_length=200)
    service: str = Field(min_length=1, max_length=80)
    severity: Severity = "medium"
    summary: str = Field(min_length=1, max_length=1000)

    @field_validator("external_id")
    @classmethod
    def _check_external_id(cls, value: str | None) -> str | None:
        if value is not None and not _EXTERNAL_ID.match(value):
            raise ValueError("external_id must match [A-Za-z0-9._:-]{1,128}")
        return value


class TelemetryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: TelemetryKind
    service: str = Field(min_length=1, max_length=80)
    timestamp: str | None = Field(default=None, max_length=40)
    payload: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def _check_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
        return value

    @field_validator("payload")
    @classmethod
    def _check_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, default=str)) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
        return value


class IngestRequest(IncidentMeta):
    telemetry: list[TelemetryIn] = Field(min_length=1, max_length=MAX_TELEMETRY_RECORDS)


class DeploymentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str = Field(min_length=1, max_length=80)
    version: str = Field(min_length=1, max_length=80)
    commit: str | None = Field(default=None, max_length=64)
    changes: str = Field(min_length=1, max_length=1000)
    deployed_at: str | None = Field(default=None, max_length=40)


class OtlpIngestRequest(BaseModel):
    """Incident envelope around an OTLP/JSON export (subset: spans, log records, gauge/sum metrics)."""

    model_config = ConfigDict(extra="forbid")
    incident: IncidentMeta
    otlp: dict[str, Any]
    deployments: list[DeploymentIn] = Field(default_factory=list, max_length=50)


class DecisionRequest(BaseModel):
    """The acting identity always comes from the authenticated principal, never from the request body."""

    note: str = Field(default="Reviewed evidence and policy result.", min_length=1, max_length=500)


class EvaluationRequest(BaseModel):
    split: Literal["dev", "heldout", "probe", "all"] = "all"
