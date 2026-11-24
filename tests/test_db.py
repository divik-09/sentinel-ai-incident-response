import sqlite3

import pytest

from backend.app.db import LATEST_SCHEMA_VERSION, Database


def _incident(db: Database, iid: str = "i1", **extra):
    return db.create_incident({"id": iid, "scenario_id": "s", "title": "t", "service": "svc", "severity": "high", "summary": "x", **extra})


def test_migrations_are_idempotent_and_versioned(tmp_path):
    path = tmp_path / "s.db"
    first = Database(path)
    assert first.schema_version() == LATEST_SCHEMA_VERSION
    first.close()
    second = Database(path)  # re-open: nothing pending
    assert second.migrate() == []
    second.close()


def test_audit_chain_verifies_and_links_events(db):
    _incident(db)
    for i in range(5):
        db.add_audit_event("i1", "alice", f"act.{i}", {"i": i})
    result = db.verify_audit_chain()
    assert result["valid"] and result["checked"] == 5 and len(result["head_hash"]) == 64


def test_audit_events_are_append_only_at_the_sql_layer(db):
    _incident(db)
    db.add_audit_event("i1", "alice", "a", {})
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db._conn.execute("UPDATE audit_events SET actor = 'mallory'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db._conn.execute("DELETE FROM audit_events")


def test_tampering_is_detected_even_if_triggers_are_bypassed(db):
    _incident(db)
    for i in range(4):
        db.add_audit_event("i1", "alice", f"a{i}", {"i": i})
    db._conn.execute("DROP TRIGGER audit_events_no_update")  # attacker with raw DB access
    db._conn.execute("UPDATE audit_events SET actor = 'mallory' WHERE id = 2")
    result = db.verify_audit_chain()
    assert not result["valid"] and result["first_invalid_event_id"] == 2


def test_deleting_a_middle_event_is_detected(db):
    _incident(db)
    for i in range(4):
        db.add_audit_event("i1", "alice", f"a{i}", {})
    db._conn.execute("DROP TRIGGER audit_events_no_delete")
    db._conn.execute("DELETE FROM audit_events WHERE id = 2")
    assert not db.verify_audit_chain()["valid"]


def test_compare_and_swap_incident_transition(db):
    _incident(db)
    assert db.transition_incident("i1", ["detected"], "investigating")
    assert not db.transition_incident("i1", ["detected"], "investigating")  # already moved
    assert db.get_incident("i1")["status"] == "investigating"


def test_external_id_is_unique_per_source(db):
    _incident(db, "a", source="api", external_id="ext-1")
    with pytest.raises(sqlite3.IntegrityError):
        _incident(db, "b", source="api", external_id="ext-1")
    _incident(db, "c", source="otlp", external_id="ext-1")  # different source: fine
    assert db.find_incident_by_external("api", "ext-1")["id"] == "a"


def test_incident_with_audit_rows_cannot_be_deleted(db):
    _incident(db)
    db.add_audit_event("i1", "alice", "a", {})
    with pytest.raises(sqlite3.DatabaseError):
        db._conn.execute("DELETE FROM incidents WHERE id = 'i1'")


def test_sim_config_roundtrip(db):
    assert db.get_sim_config("svc", "k") is None
    db.set_sim_config("svc", "k", 5)
    db.set_sim_config("svc", "k", 7)
    assert db.get_sim_config("svc", "k") == 7


def test_remediation_compare_and_swap_has_exactly_one_winner(db):
    _incident(db)
    db.create_remediation({"id": "r1", "incident_id": "i1", "action": "propose_pool_size_adjustment", "proposal": {}, "status": "proposed", "audit": []})
    assert db.transition_remediation("r1", ["proposed"], "approved", approved_by="alice") is True
    assert db.transition_remediation("r1", ["proposed"], "approved", approved_by="mallory") is False  # lost the race
    assert db.get_remediation("r1")["approved_by"] == "alice"
    assert db.transition_remediation("r1", ["approved"], "executed_in_sandbox") is True
    assert db.transition_remediation("r1", ["proposed", "approved"], "rejected") is False
