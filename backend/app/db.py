"""SQLite repository with versioned migrations and a hash-chained audit log.

Design notes
------------
* One guarded connection (``check_same_thread=False`` + ``RLock``) keeps the demo
  zero-dependency. State transitions use compare-and-swap ``UPDATE ... WHERE status IN (...)``
  so concurrent requests cannot both win a transition (e.g. double-approve).
* Schema changes are forward-only numbered migrations recorded in ``schema_migrations``.
* ``audit_events`` is append-only: SQL triggers reject UPDATE/DELETE, and every row stores
  ``prev_hash``/``hash`` (SHA-256 over the canonical record) so tampering by anyone who
  bypasses the triggers is *detectable* with :meth:`Database.verify_audit_chain`.
  Tail truncation is only detectable if the head hash is anchored externally (see docs/SECURITY.md).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import utc_now

GENESIS_HASH = "0" * 64

_M1_BASE = """
CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    title TEXT NOT NULL,
    service TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    root_cause TEXT,
    confidence REAL,
    impact TEXT,
    diagnosis_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE telemetry (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    service TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX idx_telemetry_incident_kind ON telemetry(incident_id, kind);
CREATE INDEX idx_telemetry_service ON telemetry(service);
CREATE TABLE agent_runs (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    trace_json TEXT NOT NULL,
    diagnosis_json TEXT
);
CREATE TABLE remediations (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    proposal_json TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_by TEXT,
    approval_note TEXT,
    executed_at TEXT,
    audit_json TEXT NOT NULL
);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_M2_AUDIT_CHAIN = """
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN hash TEXT;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
"""

_M3_INGEST = """
ALTER TABLE incidents ADD COLUMN source TEXT NOT NULL DEFAULT 'synthetic';
ALTER TABLE incidents ADD COLUMN external_id TEXT;
ALTER TABLE incidents ADD COLUMN created_by TEXT;
CREATE UNIQUE INDEX idx_incidents_external ON incidents(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_remediations_incident ON remediations(incident_id);
"""

_M4_SIM_CONFIG = """
CREATE TABLE sim_config (
    service TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (service, key)
);
"""

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "baseline", _M1_BASE),
    (2, "tamper_evident_audit_log", _M2_AUDIT_CHAIN),
    (3, "ingestion_and_ownership", _M3_INGEST),
    (4, "simulated_config_store", _M4_SIM_CONFIG),
]
LATEST_SCHEMA_VERSION = MIGRATIONS[-1][0]


def audit_digest(prev_hash: str, incident_id: str, actor: str, action: str, details_json: str, created_at: str) -> str:
    material = "\x1f".join([prev_hash, incident_id, actor, action, details_json, created_at])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self.migrate()

    # ------------------------------------------------------------------ infra
    def migrate(self) -> list[int]:
        """Apply any pending migrations. Idempotent; returns versions applied."""
        applied: list[int] = []
        with self._lock:
            self._conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
            done = {r["version"] for r in self._conn.execute("SELECT version FROM schema_migrations")}
            for version, name, sql in MIGRATIONS:
                if version in done:
                    continue
                script = f"BEGIN;\n{sql}\nINSERT INTO schema_migrations(version, name, applied_at) VALUES ({int(version)}, '{name}', '{utc_now()}');\nCOMMIT;"
                try:
                    self._conn.executescript(script)
                except Exception:
                    if self._conn.in_transaction:
                        self._conn.execute("ROLLBACK")
                    raise
                applied.append(version)
        return applied

    def schema_version(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
            return int(cur.fetchone()["v"])

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
                cur.execute("COMMIT")
            except Exception:
                if self._conn.in_transaction:
                    cur.execute("ROLLBACK")
                raise
            finally:
                cur.close()

    def ping(self) -> bool:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()
        return True

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    # -------------------------------------------------------------- incidents
    def create_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        item = {"source": "synthetic", "external_id": None, "created_by": None, **incident, "created_at": now, "updated_at": now}
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO incidents
                (id, scenario_id, title, service, severity, status, summary, source, external_id, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    item["id"],
                    item["scenario_id"],
                    item["title"],
                    item["service"],
                    item["severity"],
                    item.get("status", "detected"),
                    item["summary"],
                    item["source"],
                    item["external_id"],
                    item["created_by"],
                    now,
                    now,
                ),
            )
        return item

    def find_incident_by_external(self, source: str, external_id: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE source = ? AND external_id = ?", (source, external_id))
            row = self._row(cur.fetchone())
        return self._with_diagnosis(row)

    def insert_telemetry(self, records: list[dict[str, Any]]) -> None:
        with self._cursor() as cur:
            cur.executemany(
                "INSERT INTO telemetry (id, incident_id, kind, service, timestamp, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                [(r["id"], r["incident_id"], r["kind"], r["service"], r["timestamp"], json.dumps(r["payload"], separators=(",", ":"))) for r in records],
            )

    @staticmethod
    def _with_diagnosis(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        raw = row.pop("diagnosis_json", None)
        if raw:
            row["diagnosis"] = json.loads(raw)
        return row

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = self._row(cur.fetchone())
        return self._with_diagnosis(row)

    def list_incidents(self, limit: int = 50, offset: int = 0, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents"
        args: list[Any] = []
        if status:
            query += " WHERE status = ?"
            args.append(status)
        query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        with self._cursor() as cur:
            cur.execute(query, args)
            rows = [dict(r) for r in cur.fetchall()]
        for row in rows:
            row.pop("diagnosis_json", None)
        return rows

    def update_incident(self, incident_id: str, **fields: Any) -> None:
        allowed = {"status", "root_cause", "confidence", "impact", "diagnosis_json"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        updates["updated_at"] = utc_now()
        sets = ", ".join(f"{key} = ?" for key in updates)
        with self._cursor() as cur:
            cur.execute(f"UPDATE incidents SET {sets} WHERE id = ?", (*updates.values(), incident_id))

    def transition_incident(self, incident_id: str, allowed_from: Sequence[str], to_status: str, **fields: Any) -> bool:
        """Atomic compare-and-swap on incident status. Returns False if the incident was not in an allowed state."""
        allowed_cols = {"root_cause", "confidence", "impact", "diagnosis_json"}
        extra = {k: v for k, v in fields.items() if k in allowed_cols}
        sets = ", ".join(["status = ?", "updated_at = ?", *[f"{k} = ?" for k in extra]])
        placeholders = ", ".join("?" for _ in allowed_from)
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE incidents SET {sets} WHERE id = ? AND status IN ({placeholders})",
                (to_status, utc_now(), *extra.values(), incident_id, *allowed_from),
            )
            return cur.rowcount == 1

    def get_telemetry(self, incident_id: str, kind: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM telemetry WHERE incident_id = ?"
        args: list[Any] = [incident_id]
        if kind:
            query += " AND kind = ?"
            args.append(kind)
        query += " ORDER BY timestamp ASC, id ASC"
        with self._cursor() as cur:
            cur.execute(query, args)
            rows = [dict(r) for r in cur.fetchall()]
        for row in rows:
            row["payload"] = json.loads(row.pop("payload_json"))
        return rows

    # ------------------------------------------------------------- agent runs
    def save_agent_run(self, run: dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO agent_runs (id, incident_id, status, started_at, completed_at, trace_json, diagnosis_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    run["id"],
                    run["incident_id"],
                    run["status"],
                    run["started_at"],
                    run.get("completed_at"),
                    json.dumps(run.get("trace", [])),
                    json.dumps(run["diagnosis"]) if run.get("diagnosis") else None,
                ),
            )

    def latest_agent_run(self, incident_id: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM agent_runs WHERE incident_id = ? ORDER BY started_at DESC, rowid DESC LIMIT 1", (incident_id,))
            row = self._row(cur.fetchone())
        if row:
            row["trace"] = json.loads(row.pop("trace_json"))
            raw = row.pop("diagnosis_json")
            row["diagnosis"] = json.loads(raw) if raw else None
        return row

    # ----------------------------------------------------------- remediations
    def create_remediation(self, remediation: dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO remediations (id, incident_id, action, proposal_json, status, audit_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    remediation["id"],
                    remediation["incident_id"],
                    remediation["action"],
                    json.dumps(remediation["proposal"]),
                    remediation.get("status", "proposed"),
                    json.dumps(remediation.get("audit", [])),
                ),
            )

    def get_remediation(self, remediation_id: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM remediations WHERE id = ?", (remediation_id,))
            row = self._row(cur.fetchone())
        if row:
            row["proposal"] = json.loads(row.pop("proposal_json"))
            row["audit"] = json.loads(row.pop("audit_json"))
        return row

    def latest_remediation(self, incident_id: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT id FROM remediations WHERE incident_id = ? ORDER BY rowid DESC LIMIT 1", (incident_id,))
            row = cur.fetchone()
        return self.get_remediation(row["id"]) if row else None

    def update_remediation(self, remediation_id: str, **fields: Any) -> None:
        allowed = {"status", "approved_by", "approval_note", "executed_at", "audit_json"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        sets = ", ".join(f"{key} = ?" for key in updates)
        with self._cursor() as cur:
            cur.execute(f"UPDATE remediations SET {sets} WHERE id = ?", (*updates.values(), remediation_id))

    def transition_remediation(self, remediation_id: str, allowed_from: Sequence[str], to_status: str, **fields: Any) -> bool:
        allowed_cols = {"approved_by", "approval_note", "executed_at", "audit_json"}
        extra = {k: v for k, v in fields.items() if k in allowed_cols}
        sets = ", ".join(["status = ?", *[f"{k} = ?" for k in extra]])
        placeholders = ", ".join("?" for _ in allowed_from)
        with self._cursor() as cur:
            cur.execute(
                f"UPDATE remediations SET {sets} WHERE id = ? AND status IN ({placeholders})",
                (to_status, *extra.values(), remediation_id, *allowed_from),
            )
            return cur.rowcount == 1

    def supersede_open_remediations(self, incident_id: str) -> int:
        with self._cursor() as cur:
            cur.execute("UPDATE remediations SET status = 'superseded' WHERE incident_id = ? AND status = 'proposed'", (incident_id,))
            return cur.rowcount

    # ------------------------------------------------------------------ audit
    def add_audit_event(self, incident_id: str, actor: str, action: str, details: dict[str, Any]) -> str:
        created_at = utc_now()
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
        with self._cursor() as cur:
            cur.execute("SELECT hash FROM audit_events WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1")
            last = cur.fetchone()
            prev = last["hash"] if last else GENESIS_HASH
            digest = audit_digest(prev, incident_id, actor, action, details_json, created_at)
            cur.execute(
                "INSERT INTO audit_events (incident_id, actor, action, details_json, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (incident_id, actor, action, details_json, created_at, prev, digest),
            )
        return digest

    def get_audit_events(self, incident_id: str) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM audit_events WHERE incident_id = ? ORDER BY id ASC", (incident_id,))
            rows = [dict(r) for r in cur.fetchall()]
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return rows

    def verify_audit_chain(self) -> dict[str, Any]:
        """Recompute the whole hash chain. Detects edits, deletions in the middle, and reordering."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM audit_events ORDER BY id ASC")
            rows = cur.fetchall()
        expected_prev = GENESIS_HASH
        checked = legacy = 0
        for row in rows:
            if row["hash"] is None:
                legacy += 1  # written before migration 2; cannot be verified
                continue
            digest = audit_digest(row["prev_hash"] or "", row["incident_id"], row["actor"], row["action"], row["details_json"], row["created_at"])
            if row["prev_hash"] != expected_prev or digest != row["hash"]:
                return {"valid": False, "checked": checked, "first_invalid_event_id": row["id"], "legacy_unverified": legacy, "head_hash": None}
            expected_prev = row["hash"]
            checked += 1
        return {"valid": True, "checked": checked, "first_invalid_event_id": None, "legacy_unverified": legacy, "head_hash": expected_prev}

    # ------------------------------------------------------- simulated config
    def get_sim_config(self, service: str, key: str) -> Any | None:
        with self._cursor() as cur:
            cur.execute("SELECT value_json FROM sim_config WHERE service = ? AND key = ?", (service, key))
            row = cur.fetchone()
        return json.loads(row["value_json"]) if row else None

    def set_sim_config(self, service: str, key: str, value: Any) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO sim_config (service, key, value_json, updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(service, key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at""",
                (service, key, json.dumps(value), utc_now()),
            )

    # -------------------------------------------------------------- dashboard
    def dashboard_counts(self) -> dict[str, Any]:
        done = "('resolved', 'simulated', 'rejected')"
        with self._cursor() as cur:
            cur.execute(
                f"""SELECT COUNT(*) AS total,
                SUM(CASE WHEN status NOT IN {done} THEN 1 ELSE 0 END) AS open,
                SUM(CASE WHEN severity = 'critical' AND status NOT IN {done} THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN status = 'awaiting_approval' THEN 1 ELSE 0 END) AS awaiting
                FROM incidents"""
            )
            row = cur.fetchone()
        return {
            "total_incidents": row["total"] or 0,
            "open_incidents": row["open"] or 0,
            "critical_open": row["critical"] or 0,
            "awaiting_approval": row["awaiting"] or 0,
        }
