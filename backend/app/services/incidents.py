from __future__ import annotations

import uuid
from typing import Any

from ..db import Database
from ..errors import NotFoundError
from ..models import IncidentMeta, TelemetryIn, utc_now
from ..redaction import RedactionReport, sanitize
from ..scenarios import ScenarioRegistry


class IncidentService:
    def __init__(self, db: Database, scenarios: ScenarioRegistry, demo_services: Any | None = None):
        self.db = db
        self.scenarios = scenarios
        self.demo_services = demo_services

    # ---------------------------------------------------------------- creation
    def _create(
        self,
        *,
        source: str,
        scenario_id: str,
        meta: IncidentMeta | dict[str, Any],
        records: list[dict[str, Any]],
        actor: str,
        audit_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = meta.model_dump() if isinstance(meta, IncidentMeta) else dict(meta)
        external_id = data.get("external_id")
        if external_id:
            existing = self.db.find_incident_by_external(source, external_id)
            if existing:
                return {**existing, "deduplicated": True, "telemetry_count": len(self.db.get_telemetry(existing["id"]))}

        report = RedactionReport()
        title = sanitize(data["title"], report)
        summary = sanitize(data["summary"], report)
        incident_id = uuid.uuid4().hex
        incident = self.db.create_incident(
            {
                "id": incident_id,
                "scenario_id": scenario_id,
                "title": title,
                "service": data["service"][:80],
                "severity": data["severity"],
                "status": "detected",
                "summary": summary,
                "source": source,
                "external_id": external_id,
                "created_by": actor,
            }
        )
        rows = [
            {
                "id": f"ev-{incident_id[:8]}-{index:03d}",
                "incident_id": incident_id,
                "kind": rec["kind"],
                "service": str(rec["service"])[:80],
                "timestamp": rec.get("timestamp") or utc_now(),
                "payload": sanitize(rec["payload"], report),
            }
            for index, rec in enumerate(records, start=1)
        ]
        self.db.insert_telemetry(rows)
        self.db.add_audit_event(
            incident_id,
            actor,
            "incident.detected",
            {
                "source": source,
                "scenario_id": scenario_id,
                "telemetry_records_created": len(rows),
                **(audit_extra or {}),
                **report.as_dict(),
            },
        )
        return {**incident, "telemetry_count": len(rows), "deduplicated": False, "redaction": report.as_dict()}

    def trigger(self, scenario_id: str, actor: str = "system") -> dict[str, Any]:
        scenario = self.scenarios.get(scenario_id)
        if not scenario:
            raise NotFoundError("Unknown scenario")
        if self.demo_services:
            self.demo_services.activate_scenario(scenario_id)
        meta = {k: scenario[k] for k in ("title", "service", "severity", "summary")}
        return self._create(
            source="synthetic",
            scenario_id=scenario["id"],
            meta=meta,
            actor=actor,
            records=scenario["telemetry"],
            audit_extra={"environment": "synthetic_demo_data"},
        )

    def ingest(self, meta: IncidentMeta, telemetry: list[TelemetryIn] | list[dict[str, Any]], actor: str, source: str = "api") -> dict[str, Any]:
        records = [t.model_dump() if isinstance(t, TelemetryIn) else t for t in telemetry]
        return self._create(
            source=source, scenario_id=f"ingested:{source}", meta=meta, actor=actor, records=records, audit_extra={"environment": "ingested_telemetry"}
        )
