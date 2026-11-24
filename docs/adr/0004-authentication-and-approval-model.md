# ADR 0004: API-key RBAC with credential-derived identity and optional four-eyes

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

v1 had no authentication and let the *request body* name the approver (`"approved_by": "local-operator"`), so the audit trail recorded whatever the caller typed.

## Decision

- Static API keys, configured only as SHA-256 digests (`name:role:hash`); roles `viewer < operator < approver`.
- The acting identity is the authenticated principal; request-supplied identities are ignored.
- Approval is an atomic compare-and-swap; policy is re-evaluated at approval time.
- Optional four-eyes: the approver must differ from the incident's creator and its investigators (default on in staging/production).
- Secure by default: keys present ⇒ auth on; production-like environments refuse to start unauthenticated.

## Alternatives considered

OIDC/JWT (better for real deployments — listed as a next step, needs an IdP); mTLS (heavy for a demo); sessions/cookies (introduces CSRF scope).

## Consequences

Simple to run and test; weaker than SSO (no expiry, rotation by redeploy, shared secrets). Keys are bearer credentials: rotate on suspicion, keep in a secret manager.
