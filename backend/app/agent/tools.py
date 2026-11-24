from __future__ import annotations

from typing import Any

from ..db import Database
from ..services.runbooks import RunbookRetriever


class IncidentTools:
    """Allowlisted, read-only diagnostic tools exposed to the investigation workflow."""

    def __init__(self, db: Database, runbooks: RunbookRetriever):
        self.db = db
        self.runbooks = runbooks

    def _records(self, incident_id: str, kind: str) -> list[dict[str, Any]]:
        records = self.db.get_telemetry(incident_id, kind)
        return [
            {
                "evidence_id": record["id"],
                "kind": record["kind"],
                "service": record["service"],
                "timestamp": record["timestamp"],
                **record["payload"],
            }
            for record in records
        ]

    def query_metrics(self, incident_id: str) -> dict[str, Any]:
        rows = self._records(incident_id, "metric")
        return {"count": len(rows), "records": rows}

    def search_logs(self, incident_id: str) -> dict[str, Any]:
        rows = self._records(incident_id, "log")
        return {"count": len(rows), "records": rows}

    def inspect_traces(self, incident_id: str) -> dict[str, Any]:
        rows = self._records(incident_id, "trace")
        return {"count": len(rows), "records": rows}

    def deployment_history(self, incident_id: str) -> dict[str, Any]:
        rows = self._records(incident_id, "deployment")
        return {"count": len(rows), "records": rows}

    def search_runbooks(self, incident_id: str, query: str) -> dict[str, Any]:
        return {"records": self.runbooks.search(query, limit=3)}

    def execute(self, tool_name: str, incident_id: str, **kwargs: Any) -> dict[str, Any]:
        # Deliberately explicit: no dynamic eval, shell, SQL, or arbitrary tool dispatch.
        dispatch = {
            "query_metrics": self.query_metrics,
            "search_logs": self.search_logs,
            "inspect_traces": self.inspect_traces,
            "deployment_history": self.deployment_history,
        }
        if tool_name == "search_runbooks":
            return self.search_runbooks(incident_id, str(kwargs.get("query", "incident symptoms")))
        if tool_name not in dispatch:
            raise ValueError(f"Tool is not allowlisted: {tool_name}")
        return dispatch[tool_name](incident_id)
