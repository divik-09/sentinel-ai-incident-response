from __future__ import annotations

import json
from typing import Any

from backend.app.config import DATA_DIR

KIND_TO_TOOL = {"metric": "query_metrics", "log": "search_logs", "trace": "inspect_traces", "deployment": "deployment_history"}


def load_cases(split: str) -> list[dict[str, Any]]:
    if split == "dev":
        return [
            {"id": s["id"], "expected": s["expected_root_cause"], "telemetry": s["telemetry"], "tags": ["dev_fixture"]}
            for s in json.loads((DATA_DIR / "scenarios.json").read_text())
        ]
    path = DATA_DIR / "eval" / f"{split}.json"
    return [{"id": c["id"], "expected": c["expected_root_cause"], "telemetry": c["telemetry"], "tags": c.get("tags", [])} for c in json.loads(path.read_text())]


def to_tool_results(telemetry: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build the in-memory tool results the diagnosis engine consumes, without a database."""
    results: dict[str, dict[str, Any]] = {tool: {"records": []} for tool in KIND_TO_TOOL.values()}
    for index, rec in enumerate(telemetry, start=1):
        results[KIND_TO_TOOL[rec["kind"]]]["records"].append(
            {"evidence_id": f"ev-test-{index:03d}", "kind": rec["kind"], "service": rec["service"], "timestamp": "2026-11-24T00:00:00Z", **rec["payload"]}
        )
    return results
