import json
import threading

import pytest

from backend.app.agent.runtime import InvestigationAgent
from backend.app.errors import ConflictError, ForbiddenError, NotFoundError, PolicyViolationError
from backend.app.services import policy
from backend.app.services.incidents import IncidentService
from backend.app.services.remediation import RemediationService


def diagnosed(db, scenarios, runbooks, scenario_id="payment-pool-exhaustion", actor="investigator"):
    incident = IncidentService(db, scenarios).trigger(scenario_id, actor="creator")
    result = InvestigationAgent(db, runbooks).investigate(incident["id"], actor=actor)
    return incident["id"], result["remediation"]["id"], result


# ------------------------------------------------------------------------------ policy
def proposal(**overrides):
    base = {
        "action": "propose_pool_size_adjustment",
        "execution_mode": "sandbox_simulation_only",
        "requires_human_approval": True,
        "risk": "medium",
        "changes": [{"key": "database_pool.max_size", "current": 4, "proposed": 12}],
    }
    base.update(overrides)
    return base


def test_policy_allows_a_conservative_change():
    assert policy.evaluate(proposal()).allowed


@pytest.mark.parametrize(
    "mutation,fragment",
    [
        ({"action": "run_shell_command"}, "allowlist"),
        ({"execution_mode": "production"}, "sandbox_simulation_only"),
        ({"requires_human_approval": False}, "human approval"),
        ({"changes": [{"key": "database_pool.max_size", "current": 4, "proposed": 500}]}, "[1, 200]"),
        ({"changes": [{"key": "database_pool.max_size", "current": 4, "proposed": 40}]}, "4x"),
        ({"changes": [{"key": "database_pool.max_size", "current": 4, "proposed": True}]}, "integer"),
        ({"changes": [{"key": "dependency.timeout_ms", "current": 2500, "proposed": 50}]}, "[100, 30000]"),
        ({"changes": [{"key": "cache.ttl_jitter_pct", "current": 0, "proposed": 90}]}, "[5, 30]"),
        ({"changes": [{"key": "unknown.key", "current": 1, "proposed": 2}]}, "unknown configuration key"),
        ({"changes": [{"key": "database_pool.max_size", "current": 4, "proposed": None}]}, "manual review"),
    ],
)
def test_policy_blocks_unsafe_proposals(mutation, fragment):
    decision = policy.evaluate(proposal(**mutation))
    assert not decision.allowed and any(fragment in v for v in decision.violations)


@pytest.mark.parametrize(
    "statement,ok",
    [
        ("ALTER TABLE orders ADD COLUMN delivery_instructions TEXT NULL", True),
        ("ALTER TABLE orders ADD COLUMN note VARCHAR(255)", True),
        ("ALTER TABLE orders DROP COLUMN delivery_instructions", False),
        ("ALTER TABLE orders ADD COLUMN x TEXT; DROP TABLE orders", False),
        ("DROP TABLE orders", False),
        ("TRUNCATE orders", False),
        ("ALTER TABLE orders RENAME COLUMN a TO b", False),
    ],
)
def test_only_additive_single_statement_migrations_are_allowed(statement, ok):
    decision = policy.evaluate(
        {
            "action": "propose_missing_migration",
            "execution_mode": "sandbox_simulation_only",
            "requires_human_approval": True,
            "risk": "high",
            "changes": [{"key": "schema.migration", "current": None, "proposed": statement}],
        }
    )
    assert decision.allowed is ok


# -------------------------------------------------------------------------- approval flow
def test_approval_applies_change_to_sandbox_config_only(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    approved = RemediationService(db).approve_and_execute(iid, rid, "alice", "reviewed")
    assert approved["status"] == "executed_in_sandbox" and approved["approved_by"] == "alice"
    assert db.get_sim_config("payments", "database_pool.max_size") == 12
    assert db.get_incident(iid)["status"] == "simulated"
    event = db.get_audit_events(iid)[-1]
    assert event["details"]["production_change"] is False and event["actor"] == "alice"
    assert "No production system was contacted" in approved["audit"][1]["result"]


def test_rollback_restores_previous_value_and_is_audited(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    service = RemediationService(db)
    service.approve_and_execute(iid, rid, "alice", "ok")
    rolled = service.rollback(iid, rid, "alice", "undo")
    assert rolled["status"] == "rolled_back" and db.get_sim_config("payments", "database_pool.max_size") == 4
    assert db.get_incident(iid)["status"] == "rolled_back"
    assert db.get_audit_events(iid)[-1]["action"] == "remediation.rolled_back"
    with pytest.raises(ConflictError):
        service.rollback(iid, rid, "alice", "again")


def test_cannot_rollback_something_that_was_never_simulated(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    with pytest.raises(ConflictError, match="Only a simulated"):
        RemediationService(db).rollback(iid, rid, "alice", "x")


def test_second_approval_is_rejected(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks, "orders-schema-mismatch")
    service = RemediationService(db)
    service.approve_and_execute(iid, rid, "alice", "ok")
    with pytest.raises(ConflictError, match="cannot be approved"):
        service.approve_and_execute(iid, rid, "alice", "again")


def test_concurrent_approvals_have_exactly_one_winner(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    service = RemediationService(db)
    outcomes: list[str] = []
    barrier = threading.Barrier(8)

    def worker(n: int):
        barrier.wait()
        try:
            service.approve_and_execute(iid, rid, f"approver-{n}", "go")
            outcomes.append("ok")
        except ConflictError:
            outcomes.append("conflict")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert outcomes.count("ok") == 1 and outcomes.count("conflict") == 7
    assert db.get_sim_config("payments", "database_pool.max_size") == 12  # applied once, not 8 times


def test_arbitrary_action_is_blocked_by_policy_and_audited(db, scenarios):
    incident = IncidentService(db, scenarios).trigger("payment-pool-exhaustion")
    db.update_incident(incident["id"], status="awaiting_approval")
    db.create_remediation(
        {
            "id": "unsafe",
            "incident_id": incident["id"],
            "action": "run_shell_command",
            "proposal": {"title": "x", "risk": "critical"},
            "status": "proposed",
            "audit": [],
        }
    )
    with pytest.raises(PolicyViolationError, match="allowlist"):
        RemediationService(db).approve_and_execute(incident["id"], "unsafe", "alice", "no")
    assert db.get_remediation("unsafe")["status"] == "proposed"
    assert db.get_audit_events(incident["id"])[-1]["action"] == "remediation.blocked_by_policy"


def test_policy_is_rechecked_at_approval_time_against_a_tampered_proposal(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    tampered = db.get_remediation(rid)["proposal"]
    tampered["changes"][0]["proposed"] = 9999
    with db._cursor() as cur:
        cur.execute("UPDATE remediations SET proposal_json = ? WHERE id = ?", (json.dumps(tampered), rid))
    with pytest.raises(PolicyViolationError):
        RemediationService(db).approve_and_execute(iid, rid, "alice", "ok")
    assert db.get_sim_config("payments", "database_pool.max_size") is None


def test_config_drift_fails_the_simulation_without_partial_writes(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    db.set_sim_config("payments", "database_pool.max_size", 6)  # someone changed it after the proposal was made
    with pytest.raises(ConflictError, match="drift"):
        RemediationService(db).approve_and_execute(iid, rid, "alice", "ok")
    assert db.get_sim_config("payments", "database_pool.max_size") == 6
    assert db.get_remediation(rid)["status"] == "failed"


def test_unknown_diagnosis_cannot_be_approved(db, scenarios, runbooks):
    incident = IncidentService(db, scenarios).trigger("payment-pool-exhaustion")
    with db._cursor() as cur:
        cur.execute("DELETE FROM telemetry WHERE incident_id = ?", (incident["id"],))
    result = InvestigationAgent(db, runbooks).investigate(incident["id"])
    assert result["incident"]["status"] == "diagnosed" and result["remediation"]["proposal"]["action"] == "manual_investigation_required"
    with pytest.raises(ConflictError, match="not awaiting approval"):
        RemediationService(db).approve_and_execute(incident["id"], result["remediation"]["id"], "alice", "x")


def test_reject_is_final_and_unknown_ids_404(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    service = RemediationService(db)
    assert service.reject(iid, rid, "alice", "no")["status"] == "rejected"
    with pytest.raises(ConflictError):
        service.approve_and_execute(iid, rid, "alice", "x")
    with pytest.raises(NotFoundError):
        service.reject(iid, "nope", "alice", "x")
    with pytest.raises(NotFoundError):
        service.approve_and_execute("nope", rid, "alice", "x")


def test_remediation_from_another_incident_is_not_accepted(db, scenarios, runbooks):
    _, rid, _ = diagnosed(db, scenarios, runbooks)
    other = IncidentService(db, scenarios).trigger("orders-schema-mismatch")
    with pytest.raises(NotFoundError):
        RemediationService(db).approve_and_execute(other["id"], rid, "alice", "x")


# ---------------------------------------------------------------------------- four eyes
def test_four_eyes_blocks_creator_and_investigator_but_allows_a_third_person(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks, actor="investigator")
    service = RemediationService(db, four_eyes=True)
    for actor in ("creator", "investigator"):
        with pytest.raises(ForbiddenError, match="Four-eyes"):
            service.approve_and_execute(iid, rid, actor, "x")
    assert db.get_remediation(rid)["status"] == "proposed"
    assert service.approve_and_execute(iid, rid, "third-person", "ok")["status"] == "executed_in_sandbox"


def test_reinvestigation_supersedes_open_proposals(db, scenarios, runbooks):
    iid, first_rid, _ = diagnosed(db, scenarios, runbooks)
    second = InvestigationAgent(db, runbooks).investigate(iid)
    assert db.get_remediation(first_rid)["status"] == "superseded"
    assert second["remediation"]["id"] != first_rid and second["remediation"]["status"] == "proposed"
    with pytest.raises(ConflictError):
        RemediationService(db).approve_and_execute(iid, first_rid, "alice", "stale")


def test_cannot_investigate_a_finished_incident_or_one_already_running(db, scenarios, runbooks):
    iid, rid, _ = diagnosed(db, scenarios, runbooks)
    RemediationService(db).approve_and_execute(iid, rid, "alice", "ok")
    with pytest.raises(ConflictError):
        InvestigationAgent(db, runbooks).investigate(iid)
    other = IncidentService(db, scenarios).trigger("orders-schema-mismatch")
    db.update_incident(other["id"], status="investigating")
    with pytest.raises(ConflictError, match="already running"):
        InvestigationAgent(db, runbooks).investigate(other["id"])


def test_failed_investigation_restores_status_and_is_audited(db, scenarios, runbooks, monkeypatch):
    incident = IncidentService(db, scenarios).trigger("payment-pool-exhaustion")
    monkeypatch.setattr("backend.app.agent.runtime.diagnose", lambda _r: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        InvestigationAgent(db, runbooks).investigate(incident["id"])
    assert db.get_incident(incident["id"])["status"] == "detected"
    assert db.get_audit_events(incident["id"])[-1]["action"] == "investigation.failed"


def test_proposals_per_cause_are_policy_compliant(db, scenarios, runbooks):
    for scenario in scenarios.all():
        _, _, result = diagnosed(db, scenarios, runbooks, scenario["id"])
        proposal_ = result["remediation"]["proposal"]
        assert proposal_["policy"]["allowed"], (scenario["id"], proposal_["policy"])
