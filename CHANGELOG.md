# Changelog

## 2.0.0

**Diagnosis**
- Replaced the hardcoded `if` chain with a declarative weighted-signal rule catalogue (`agent/rules.py`); scale/unit normalisation, name-pattern matching, per-metric thresholds.
- Added explicit **abstention** (insufficient or conflicting evidence), ≥2-independent-kind corroboration, and "what to collect next" hints.
- Evidence-coverage score replaces invented confidence constants; `unknown` now has `confidence: null`.
- Fixed: raw byte/count metrics with no limit were treated as utilisation ratios.

**Security & safety**
- API-key auth, RBAC, credential-derived identity, four-eyes, rate limiting, failed-auth throttling, body limit, security headers/CSP, fail-closed production config.
- Redaction of secrets/PII at ingest and before model calls; instruction-like telemetry excluded from rule matching and reported.
- LLM planner hardened (allowlist/budgets/untrusted envelope/retries/circuit breaker) and tested against a scripted hostile model; client moved from `urllib` to `httpx`.
- Remediation: structured proposals, policy-as-code (re-checked at approval), atomic approval (CAS), drift detection, read-back verification, **rollback**.
- Audit log: append-only triggers + SHA-256 hash chain + `/api/audit/verify`.

**Platform**
- App factory + services container (no import-time side effects); versioned DB migrations; structured JSON logs with request IDs; Prometheus metrics; `/api/ready`.
- Ingestion API (`/api/incidents/ingest`) with idempotency keys and an OTLP/JSON adapter.
- Incident lifecycle fixes: atomic investigation claim, superseded proposals on re-investigation, no re-investigation of finished incidents.

**Quality**
- Evaluation: dev + 36 held-out + 12 probe cases; wrong-diagnosis rate, coverage, abstention precision/recall, Brier/ECE, evidence precision/recall; CI regression gate.
- 347 tests (was 14), 94% branch coverage, metamorphic/property tests, mutation-checked controls, ruff + mypy + pip-audit in CI.
- Hardened multi-stage Docker image (non-root, read-only FS, healthcheck); compose with dropped capabilities.

**Breaking changes**
- Run with `--factory`: `uvicorn backend.app.main:create_app --factory` (was `backend.app.main:app`).
- Approve/reject bodies no longer accept an actor; identity comes from the credential.
- `confidence` is `null` when abstaining.

## 1.0.0
Initial portfolio release.
