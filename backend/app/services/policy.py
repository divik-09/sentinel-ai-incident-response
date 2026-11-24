"""Policy-as-code for remediation. Evaluated when a proposal is created *and again* at approval time."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

POLICY_VERSION = "1.0"
ALLOWED_ACTIONS = {
    "propose_pool_size_adjustment",
    "propose_dependency_timeout_and_circuit_breaker",
    "propose_missing_migration",
    "propose_cache_ttl_jitter",
    "propose_memory_retention_investigation",
}
_ADDITIVE_MIGRATION = re.compile(r"^ALTER TABLE [A-Za-z_]\w* ADD COLUMN [A-Za-z_]\w* [A-Z]+(\(\d+\))?( NULL)?;?$")
_DESTRUCTIVE = re.compile(r"\b(DROP|TRUNCATE|DELETE|RENAME|ALTER\s+COLUMN|GRANT|REVOKE)\b", re.I)


@dataclass
class PolicyDecision:
    allowed: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    policy_version: str = POLICY_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "violations": self.violations, "warnings": self.warnings, "policy_version": self.policy_version}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def evaluate(proposal: dict[str, Any]) -> PolicyDecision:
    violations: list[str] = []
    warnings: list[str] = []
    action = proposal.get("action")

    if action not in ALLOWED_ACTIONS:
        violations.append(f"action '{action}' is not on the remediation allowlist")
        return PolicyDecision(False, violations, warnings)
    if proposal.get("execution_mode") != "sandbox_simulation_only":
        violations.append("only sandbox_simulation_only execution is permitted")
    if proposal.get("requires_human_approval") is not True:
        violations.append("proposal must require human approval")

    for change in proposal.get("changes", []):
        key, current, proposed = change.get("key"), change.get("current"), change.get("proposed")
        if proposed is None:
            violations.append(f"{key}: no concrete proposed value; manual review required")
            continue
        if key == "database_pool.max_size":
            if not _is_int(proposed) or not 1 <= proposed <= 200:
                violations.append("database_pool.max_size must be an integer in [1, 200]")
            elif _is_int(current) and proposed > 4 * current:
                violations.append("database_pool.max_size may not increase by more than 4x in one change")
        elif key == "dependency.timeout_ms":
            if not _is_int(proposed) or not 100 <= proposed <= 30000:
                violations.append("dependency.timeout_ms must be an integer in [100, 30000]")
        elif key == "cache.ttl_jitter_pct":
            if not _is_int(proposed) or not 5 <= proposed <= 30:
                violations.append("cache.ttl_jitter_pct must be an integer in [5, 30]")
        elif key in {"dependency.circuit_breaker.enabled", "cache.single_flight.enabled"}:
            if not isinstance(proposed, bool):
                violations.append(f"{key} must be a boolean")
        elif key == "schema.migration":
            statement = str(proposed)
            if _DESTRUCTIVE.search(statement) or not _ADDITIVE_MIGRATION.match(statement):
                violations.append("schema migration must be a single additive 'ALTER TABLE ... ADD COLUMN' statement")
        else:
            violations.append(f"unknown configuration key '{key}'")

    if proposal.get("risk") == "high":
        warnings.append("high-risk change: second-person approval is strongly recommended")
    return PolicyDecision(not violations, violations, warnings)
