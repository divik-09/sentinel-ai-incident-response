"""Remediation *proposals*. Creating a proposal never changes anything.

Each proposal is structured data (``changes`` with current/proposed values) so that the policy engine can
validate it and the sandbox simulator can apply and roll it back deterministically.
Defaults below seed the *simulated* config store; they are illustrative and not read from any real system.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

# (service-agnostic) default simulated config, keyed by config key
SIM_DEFAULTS: dict[str, Any] = {
    "database_pool.max_size": 4,
    "dependency.timeout_ms": 2500,
    "dependency.circuit_breaker.enabled": False,
    "cache.ttl_jitter_pct": 0,
    "cache.single_flight.enabled": False,
}

_MIGRATION_PATTERNS = (
    re.compile(r'column\s+"?(?P<col>\w+)"?\s+of\s+relation\s+"?(?P<table>\w+)"?', re.I),
    re.compile(r'column\s+"?(?P<col>\w+)"?\s+does not exist in\s+"?(?P<table>\w+)"?\s+table', re.I),
    re.compile(r"no such column:\s*(?P<table>\w+)\.(?P<col>\w+)", re.I),
)


def _extract_missing_column(evidence: list[dict[str, Any]]) -> tuple[str, str] | None:
    for item in evidence:
        if item.get("kind") != "log":
            continue
        for pattern in _MIGRATION_PATTERNS:
            match = pattern.search(str(item.get("message", "")))
            if match:
                return match.group("table"), match.group("col")
    return None


def _change(key: str, proposed: Any, current_lookup: Callable[[str], Any]) -> dict[str, Any]:
    return {"key": key, "current": current_lookup(key), "proposed": proposed}


TEMPLATES: dict[str, dict[str, Any]] = {
    "database_connection_pool_exhaustion": {
        "action": "propose_pool_size_adjustment",
        "kind": "config",
        "risk": "medium",
        "title": "Validate and cautiously restore database pool capacity",
        "description": "The pool is saturated and traces show connection acquisition waits. Verify the database connection limit and worker concurrency, then test a conservative pool-size increase in staging.",
        "tests": [
            "Verify database max_connections has sufficient headroom.",
            "Run a 10-minute checkout load test at expected peak concurrency.",
            "Confirm pool wait p95 falls below 100 ms and no connection leak appears.",
        ],
        "rollback": "Restore database_pool.max_size to its previous value and restart only the affected worker group.",
    },
    "downstream_dependency_latency": {
        "action": "propose_dependency_timeout_and_circuit_breaker",
        "kind": "config",
        "risk": "medium",
        "title": "Bound downstream waits and prevent retry amplification",
        "description": "The dependency dominates trace latency. Validate the provider, then use a bounded timeout, a circuit breaker and a business-safe fallback rather than increasing retries.",
        "tests": [
            "Run contract tests against slow and unavailable dependency responses.",
            "Verify retries are bounded and do not amplify traffic.",
            "Confirm flows fail fast or use a tested fallback.",
        ],
        "rollback": "Restore the previous timeout and circuit-breaker configuration.",
    },
    "database_schema_mismatch": {
        "action": "propose_missing_migration",
        "kind": "migration",
        "risk": "high",
        "title": "Validate the missing schema migration",
        "description": "The application expects a column the database does not expose. Check the migration ledger and prepare an additive, backward-compatible migration before deploying code that depends on it.",
        "tests": [
            "Verify the migration is absent from the target database ledger.",
            "Apply it to a production-like database snapshot.",
            "Run compatibility tests against both old and new application versions.",
        ],
        "rollback": "Roll back the application to the last schema-compatible version. Never automatically drop the column.",
    },
    "cache_stampede": {
        "action": "propose_cache_ttl_jitter",
        "kind": "config",
        "risk": "medium",
        "title": "Reduce synchronized cache misses",
        "description": "Cache hit rate has collapsed while database read QPS is elevated. Introduce request coalescing and TTL jitter for hot keys after load testing.",
        "tests": [
            "Replay a synchronized expiry workload.",
            "Verify only one refresh occurs per hot key during concurrent misses.",
            "Confirm database QPS and p95 latency return to the agreed range.",
        ],
        "rollback": "Restore the previous TTL policy and disable request coalescing if stale data or latency increases.",
    },
    "memory_pressure": {
        "action": "propose_memory_retention_investigation",
        "kind": "investigation",
        "risk": "medium",
        "title": "Investigate retained objects before changing memory limits",
        "description": "Memory usage and OOM restarts are elevated. Capture a heap profile in staging and inspect unbounded caches or retained references before increasing container limits.",
        "tests": [
            "Run a 30-minute soak test with representative traffic.",
            "Compare heap growth and RSS after warm-up.",
            "Verify worker restarts remain at zero during the test.",
        ],
        "rollback": "Revert the application change and restore the previously validated resource limit.",
    },
}


def create_proposal(diagnosis: dict[str, Any], incident_service: str = "unknown", current_lookup: Callable[[str], Any] | None = None) -> dict[str, Any]:
    lookup = current_lookup or (lambda key: SIM_DEFAULTS.get(key))
    template = TEMPLATES.get(diagnosis["root_cause"])
    if not template:
        return {
            "action": "manual_investigation_required",
            "kind": "none",
            "title": "Collect more evidence before remediation",
            "description": "The available telemetry does not support a safe automated remediation. Ask an operator to inspect the incident and collect additional evidence.",
            "service": incident_service,
            "changes": [],
            "change": "No changes proposed.",
            "missing_evidence": diagnosis.get("missing_signals", []),
            "tests": ["Collect the missing evidence listed above.", "Re-run the investigation after new evidence is available."],
            "risk": "high",
            "rollback": "No action has been taken.",
            "execution_mode": "none",
            "requires_human_approval": True,
        }

    proposal: dict[str, Any] = {**template, "service": incident_service, "execution_mode": "sandbox_simulation_only", "requires_human_approval": True}
    changes: list[dict[str, Any]] = []
    cause = diagnosis["root_cause"]
    if cause == "database_connection_pool_exhaustion":
        current = lookup("database_pool.max_size")
        changes = [{"key": "database_pool.max_size", "current": current, "proposed": min(int(current) * 3, 12) if isinstance(current, int) else None}]
    elif cause == "downstream_dependency_latency":
        changes = [_change("dependency.timeout_ms", 900, lookup), _change("dependency.circuit_breaker.enabled", True, lookup)]
    elif cause == "cache_stampede":
        changes = [_change("cache.ttl_jitter_pct", 15, lookup), _change("cache.single_flight.enabled", True, lookup)]
    elif cause == "database_schema_mismatch":
        found = _extract_missing_column(diagnosis.get("evidence", []))
        statement = f"ALTER TABLE {found[0]} ADD COLUMN {found[1]} TEXT NULL" if found else None
        changes = [{"key": "schema.migration", "current": None, "proposed": statement}]
    proposal["changes"] = changes
    proposal["change"] = _describe(changes, template["kind"], incident_service)
    return proposal


def _describe(changes: list[dict[str, Any]], kind: str, service: str) -> str:
    if kind == "investigation":
        return "No configuration change. Proposed code investigation: bound the request cache and add eviction/TTL metrics."
    if not changes:
        return "No changes proposed."
    if kind == "migration":
        stmt = changes[0]["proposed"]
        return (
            f"Additive migration (sandbox only): {stmt}"
            if stmt
            else "A concrete migration statement could not be derived from the evidence; manual review required."
        )
    return "Sandbox config change: " + "; ".join(f"{service}.{c['key']}: {c['current']!r} -> {c['proposed']!r}" for c in changes)
