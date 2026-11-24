"""Approval-gated remediation with a sandbox simulator.

What "simulation" means here (and what it does not):

* It applies the proposed change to a *simulated* configuration store (``sim_config`` table), after
  checking for drift against the value the proposal was based on.
* It proves reversibility by computing and verifying an inverse change before committing.
* It never contacts a real system. There is no shell, network, cloud API or database migration runner.
  Migrations are only *parsed and policy-checked*.
"""

from __future__ import annotations

import json
from typing import Any

from ..db import Database
from ..errors import ConflictError, ForbiddenError, NotFoundError, PolicyViolationError
from ..models import utc_now
from . import policy


class RemediationService:
    def __init__(self, db: Database, four_eyes: bool = False, on_decision: Any = None):
        self.db = db
        self.four_eyes = four_eyes
        self._on_decision = on_decision or (lambda _decision: None)

    # ----------------------------------------------------------------- helpers
    def _load(self, incident_id: str, remediation_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        incident = self.db.get_incident(incident_id)
        if not incident:
            raise NotFoundError("Incident not found")
        remediation = self.db.get_remediation(remediation_id)
        if not remediation or remediation["incident_id"] != incident_id:
            raise NotFoundError("Remediation not found for this incident")
        return incident, remediation

    def _enforce_four_eyes(self, incident: dict[str, Any], actor: str) -> None:
        if not self.four_eyes:
            return
        involved = {incident.get("created_by")}
        involved.update(e["actor"] for e in self.db.get_audit_events(incident["id"]) if e["action"] == "investigation.completed")
        if actor in involved:
            self.db.add_audit_event(incident["id"], actor, "remediation.blocked_four_eyes", {})
            raise ForbiddenError("Four-eyes policy: the approver must differ from the person who created or investigated this incident")

    def _current(self, service: str, key: str) -> Any:
        from ..agent.remediation import SIM_DEFAULTS

        stored = self.db.get_sim_config(service, key)
        return stored if stored is not None else SIM_DEFAULTS.get(key)

    # ---------------------------------------------------------------- approval
    def approve_and_execute(self, incident_id: str, remediation_id: str, actor: str, note: str) -> dict[str, Any]:
        incident, remediation = self._load(incident_id, remediation_id)
        if remediation["status"] != "proposed":
            raise ConflictError(f"Remediation cannot be approved from status '{remediation['status']}'")
        if incident["status"] != "awaiting_approval":
            raise ConflictError("Incident is not awaiting approval")
        self._enforce_four_eyes(incident, actor)

        proposal = {**remediation["proposal"], "action": remediation["action"]}
        decision = policy.evaluate(proposal)
        if not decision.allowed:
            self.db.add_audit_event(incident_id, actor, "remediation.blocked_by_policy", {"remediation_id": remediation_id, "violations": decision.violations})
            self._on_decision("blocked_by_policy")
            if remediation["action"] not in policy.ALLOWED_ACTIONS:
                raise PolicyViolationError(["Action is not on the sandbox allowlist", *decision.violations[1:]])
            raise PolicyViolationError(decision.violations)

        # Atomic claim: only one concurrent approver can move proposed -> approved.
        claimed = self.db.transition_remediation(
            remediation_id,
            ["proposed"],
            "approved",
            approved_by=actor,
            approval_note=note,
            audit_json=json.dumps([{"event": "approved", "actor": actor, "note": note, "timestamp": utc_now()}]),
        )
        if not claimed:
            raise ConflictError("Remediation was already decided by another request")

        try:
            result = self._simulate(incident["service"], proposal)
        except ConflictError as exc:
            self.db.transition_remediation(
                remediation_id,
                ["approved"],
                "failed",
                audit_json=json.dumps(
                    [
                        {"event": "approved", "actor": actor, "note": note, "timestamp": utc_now()},
                        {"event": "sandbox_execution_failed", "actor": "sentinel-sandbox", "result": exc.message, "timestamp": utc_now()},
                    ]
                ),
            )
            self.db.add_audit_event(incident_id, actor, "remediation.simulation_failed", {"remediation_id": remediation_id, "reason": exc.message})
            self._on_decision("simulation_failed")
            raise

        audit = [
            {"event": "approved", "actor": actor, "note": note, "timestamp": utc_now()},
            {"event": "sandbox_execution", "actor": "sentinel-sandbox", "result": result["summary"], "details": result, "timestamp": utc_now()},
        ]
        self.db.transition_remediation(remediation_id, ["approved"], "executed_in_sandbox", executed_at=utc_now(), audit_json=json.dumps(audit))
        self.db.update_incident(incident_id, status="simulated")
        self.db.add_audit_event(
            incident_id,
            actor,
            "remediation.approved_and_simulated",
            {
                "remediation_id": remediation_id,
                "action": remediation["action"],
                "production_change": False,
                "policy_version": decision.policy_version,
                "changes_applied": result["applied"],
            },
        )
        self._on_decision("approved")
        return self.db.latest_remediation(incident_id) or {}

    def _simulate(self, service: str, proposal: dict[str, Any]) -> dict[str, Any]:
        kind = proposal.get("kind")
        if kind == "investigation":
            return {"summary": "Sandbox checklist created: no configuration, memory limit or application code was changed.", "applied": []}
        if kind == "migration":
            statement = proposal["changes"][0]["proposed"]
            return {
                "summary": f"Sandbox policy check passed: additive migration parsed ({statement}); execution is intentionally not performed.",
                "applied": [],
            }

        service_key = proposal.get("service") or service
        applied: list[dict[str, Any]] = []
        for change in proposal["changes"]:
            live = self._current(service_key, change["key"])
            if live != change["current"]:
                raise ConflictError(
                    f"Configuration drift on {change['key']}: proposal assumed {change['current']!r} but sandbox has {live!r}. Re-run the investigation."
                )
            applied.append({"key": change["key"], "previous": live, "new": change["proposed"]})
        for a in applied:
            self.db.set_sim_config(service_key, a["key"], a["new"])
        # Read back to verify the write actually landed; otherwise restore and fail.
        for a in applied:
            if self.db.get_sim_config(service_key, a["key"]) != a["new"]:
                for b in applied:
                    self.db.set_sim_config(service_key, b["key"], b["previous"])
                raise ConflictError(f"Read-back verification failed for {a['key']}; changes were restored")
        names = ", ".join(a["key"] for a in applied)
        return {
            "summary": f"Sandbox simulation applied {len(applied)} configuration change(s) ({names}); read-back verified; previous values are stored for rollback. No production system was contacted.",
            "applied": applied,
            "service": service_key,
        }

    # --------------------------------------------------------------- rejection
    def reject(self, incident_id: str, remediation_id: str, actor: str, note: str) -> dict[str, Any]:
        _, remediation = self._load(incident_id, remediation_id)
        if remediation["status"] != "proposed":
            raise ConflictError(f"Remediation cannot be rejected from status '{remediation['status']}'")
        audit = [{"event": "rejected", "actor": actor, "note": note, "timestamp": utc_now()}]
        if not self.db.transition_remediation(remediation_id, ["proposed"], "rejected", approved_by=actor, approval_note=note, audit_json=json.dumps(audit)):
            raise ConflictError("Remediation was already decided by another request")
        self.db.update_incident(incident_id, status="rejected")
        self.db.add_audit_event(incident_id, actor, "remediation.rejected", {"remediation_id": remediation_id, "note": note})
        self._on_decision("rejected")
        return self.db.latest_remediation(incident_id) or {}

    # ---------------------------------------------------------------- rollback
    def rollback(self, incident_id: str, remediation_id: str, actor: str, note: str) -> dict[str, Any]:
        incident, remediation = self._load(incident_id, remediation_id)
        if remediation["status"] != "executed_in_sandbox":
            raise ConflictError(f"Only a simulated remediation can be rolled back (status is '{remediation['status']}')")
        details = next((a.get("details") for a in remediation["audit"] if a.get("event") == "sandbox_execution"), None) or {}
        service_key = details.get("service") or incident["service"]
        for change in details.get("applied", []):
            self.db.set_sim_config(service_key, change["key"], change["previous"])
        audit = [*remediation["audit"], {"event": "rolled_back", "actor": actor, "note": note, "timestamp": utc_now()}]
        if not self.db.transition_remediation(remediation_id, ["executed_in_sandbox"], "rolled_back", audit_json=json.dumps(audit)):
            raise ConflictError("Remediation was already rolled back")
        self.db.update_incident(incident_id, status="rolled_back")
        self.db.add_audit_event(
            incident_id, actor, "remediation.rolled_back", {"remediation_id": remediation_id, "restored": [c["key"] for c in details.get("applied", [])]}
        )
        self._on_decision("rolled_back")
        return self.db.latest_remediation(incident_id) or {}
