# ADR 0003: Append-only audit table with a hash chain

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

v1 described its audit table as "immutable" but it was an ordinary table; anyone with write access could edit history silently.

## Decision

1. SQL triggers reject `UPDATE`/`DELETE` on `audit_events` (blocks accidental and application-level tampering; also blocks cascading incident deletes).
2. Each row stores `prev_hash` and `hash = SHA-256(prev_hash ‖ incident_id ‖ actor ‖ action ‖ canonical_details ‖ created_at)`.
3. `GET /api/audit/verify` recomputes the chain and returns the first invalid event id plus the current `head_hash`.

## Consequences

- (+) Edits, mid-chain deletions and reordering are detectable **even if the triggers are dropped** (tested).
- (−) **Tail truncation is not detectable** from inside the database. Operators should periodically store `head_hash` externally (documented in SECURITY/OPERATIONS).
- (−) The chain is global, so inserts serialise on the last hash; acceptable at this scale, a per-tenant chain would be needed later.
- (−) Rows written before migration 2 are reported as `legacy_unverified`.
