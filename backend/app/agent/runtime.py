from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from ..db import Database
from ..errors import ConflictError, NotFoundError
from ..models import utc_now
from ..services import policy
from ..services.runbooks import RunbookRetriever
from .diagnosis import diagnose
from .llm_review import OptionalLLMReviewer
from .remediation import SIM_DEFAULTS, create_proposal
from .tools import IncidentTools

INVESTIGABLE_STATES = ("detected", "diagnosed", "awaiting_approval")


class InvestigationAgent:
    """A bounded, inspectable agent workflow with allowlisted read-only tools."""

    TOOL_SEQUENCE = [
        ("query_metrics", "Inspect service-level metrics and threshold breaches."),
        ("search_logs", "Search logs for errors and correlated request identifiers."),
        ("inspect_traces", "Inspect distributed spans to locate where latency or failure occurs."),
        ("deployment_history", "Correlate the incident with recent service deployments."),
    ]

    def __init__(
        self,
        db: Database,
        runbooks: RunbookRetriever,
        reviewer: OptionalLLMReviewer | None = None,
        planner: Any | None = None,
        on_complete: Callable[[str, float, str], None] | None = None,
    ):
        self.db = db
        self.tools = IncidentTools(db, runbooks)
        self.reviewer = reviewer
        self.planner = planner
        self._on_complete = on_complete or (lambda _cause, _seconds, _mode: None)

    def _sim_lookup(self, service: str) -> Callable[[str], Any]:
        def lookup(key: str) -> Any:
            stored = self.db.get_sim_config(service, key)
            return stored if stored is not None else SIM_DEFAULTS.get(key)

        return lookup

    def investigate(self, incident_id: str, actor: str = "system") -> dict[str, Any]:
        incident = self.db.get_incident(incident_id)
        if not incident:
            raise NotFoundError("Incident not found")
        previous_status = incident["status"]
        if previous_status == "investigating":
            raise ConflictError("An investigation is already running for this incident")
        if not self.db.transition_incident(incident_id, INVESTIGABLE_STATES, "investigating"):
            raise ConflictError(f"Incident in status '{previous_status}' cannot be investigated again")

        started_perf = time.perf_counter()
        try:
            return self._run(incident, actor, started_perf)
        except Exception as exc:
            self.db.update_incident(incident_id, status=previous_status)
            self.db.add_audit_event(incident_id, actor, "investigation.failed", {"error": type(exc).__name__})
            raise

    def _run(self, incident: dict[str, Any], actor: str, started_perf: float) -> dict[str, Any]:
        incident_id = incident["id"]
        run_id = uuid.uuid4().hex
        started_at = utc_now()
        trace: list[dict[str, Any]] = []
        results: dict[str, dict[str, Any]] = {}
        extra_warnings: list[dict[str, Any]] = []
        mode = "deterministic"

        if self.planner:
            try:
                planned = self.planner.collect(incident, incident_id, self.tools)
            except Exception:
                planned = {"results": {}, "trace": [], "available": False}
            results.update(planned.get("results", {}))
            trace.extend(planned.get("trace", []))
            trace = [dict(item, step=index + 1) for index, item in enumerate(trace)]
            if planned.get("available"):
                mode = "llm_planned"
                trace.append(
                    {
                        "step": len(trace) + 1,
                        "type": "planner",
                        "tool": "llm_tool_planner",
                        "status": "completed",
                        "rationale": "Model selected diagnostic tools; final diagnosis remains evidence-rule based.",
                        "timestamp": utc_now(),
                    }
                )
            if planned.get("rejected_calls"):
                extra_warnings.append(
                    {
                        "type": "rejected_tool_calls",
                        "message": f"The model requested {planned['rejected_calls']} non-allowlisted or duplicate tool call(s); all were rejected.",
                    }
                )
            if (planned.get("redaction") or {}).get("injection_flags"):
                extra_warnings.append(
                    {
                        "type": "instruction_like_telemetry_sent_to_model",
                        "message": "Telemetry sent to the model contained instruction-like text and was wrapped as untrusted data.",
                    }
                )

        for tool_name, rationale in self.TOOL_SEQUENCE:
            if tool_name in results:
                continue
            started = datetime.now(UTC)
            result = self.tools.execute(tool_name, incident_id)
            results[tool_name] = result
            trace.append(
                {
                    "step": len(trace) + 1,
                    "type": "tool_call",
                    "tool": tool_name,
                    "mode": "deterministic_fallback",
                    "rationale": rationale,
                    "status": "completed",
                    "duration_ms": round((datetime.now(UTC) - started).total_seconds() * 1000, 2),
                    "result_count": result.get("count", len(result.get("records", []))),
                    "timestamp": utc_now(),
                }
            )

        diagnosis = diagnose(results)
        diagnosis["warnings"] = [*diagnosis.get("warnings", []), *extra_warnings]
        runbook_query = " ".join([diagnosis["label"], incident["service"], *diagnosis.get("signals", [])])
        runbook_started = time.perf_counter()
        runbook_result = self.tools.execute("search_runbooks", incident_id, query=runbook_query)
        results["search_runbooks"] = runbook_result
        trace.append(
            {
                "step": len(trace) + 1,
                "type": "tool_call",
                "tool": "search_runbooks",
                "rationale": "Retrieve operational guidance relevant to the evidence-backed diagnosis.",
                "status": "completed",
                "duration_ms": round((time.perf_counter() - runbook_started) * 1000, 2),
                "result_count": len(runbook_result.get("records", [])),
                "timestamp": utc_now(),
            }
        )

        evidence_by_id: dict[str, dict[str, Any]] = {}
        for tool_name in ("query_metrics", "search_logs", "inspect_traces", "deployment_history"):
            for item in results[tool_name].get("records", []):
                evidence_by_id[item["evidence_id"]] = item
        cited = [evidence_by_id[i] for i in diagnosis.get("evidence_ids", []) if i in evidence_by_id]
        diagnosis["evidence"] = cited
        diagnosis["runbooks"] = runbook_result.get("records", [])

        if self.reviewer:
            review = self.reviewer.review(diagnosis, cited)
            if review:
                diagnosis["model_review"] = review
                trace.append(
                    {
                        "step": len(trace) + 1,
                        "type": "model_review",
                        "tool": "optional_llm_reviewer",
                        "rationale": "Request a non-authoritative second opinion over collected evidence.",
                        "status": "unavailable" if review.get("unavailable") else "completed",
                        "timestamp": utc_now(),
                    }
                )

        proposal = create_proposal(diagnosis, incident["service"], self._sim_lookup(incident["service"]))
        decision = policy.evaluate(proposal) if proposal["action"] != "manual_investigation_required" else None
        proposal["policy"] = (
            decision.as_dict()
            if decision
            else {"allowed": False, "violations": ["no automated action is proposed"], "warnings": [], "policy_version": policy.POLICY_VERSION}
        )
        diagnosis["remediation_proposal"] = proposal
        trace.append(
            {
                "step": len(trace) + 1,
                "type": "decision",
                "tool": "remediation_policy",
                "rationale": "Create a non-executable proposal and evaluate it against policy; production-changing actions are never executed.",
                "status": "proposal_created",
                "risk": proposal.get("risk"),
                "policy_allowed": proposal["policy"]["allowed"],
                "timestamp": utc_now(),
            }
        )

        self.db.supersede_open_remediations(incident_id)
        remediation_id = uuid.uuid4().hex
        self.db.create_remediation(
            {"id": remediation_id, "incident_id": incident_id, "action": proposal["action"], "proposal": proposal, "status": "proposed", "audit": []}
        )
        diagnosis["remediation_id"] = remediation_id
        status = "awaiting_approval" if diagnosis["root_cause"] != "unknown" else "diagnosed"
        self.db.update_incident(
            incident_id,
            status=status,
            root_cause=diagnosis["root_cause"],
            confidence=diagnosis["confidence"],
            impact=diagnosis["impact"],
            diagnosis_json=json.dumps(diagnosis),
        )
        run = {
            "id": run_id,
            "incident_id": incident_id,
            "status": "completed",
            "started_at": started_at,
            "completed_at": utc_now(),
            "trace": trace,
            "diagnosis": diagnosis,
        }
        self.db.save_agent_run(run)
        self.db.add_audit_event(
            incident_id,
            actor,
            "investigation.completed",
            {
                "run_id": run_id,
                "root_cause": diagnosis["root_cause"],
                "abstain_reason": diagnosis.get("abstain_reason"),
                "ruleset_version": diagnosis["ruleset_version"],
                "mode": mode,
                "evidence_count": diagnosis["evidence_count"],
                "warnings": [w["type"] for w in diagnosis["warnings"]],
            },
        )
        self._on_complete(diagnosis["root_cause"], time.perf_counter() - started_perf, mode)
        return {"run": run, "incident": self.db.get_incident(incident_id), "remediation": self.db.latest_remediation(incident_id)}
