# Security

Sentinel is a single-node service that handles incident telemetry and gates remediation. This document separates **what is implemented and tested** from
**what is still required** before exposing it beyond a trusted network. It has not had an independent security review.

## Implemented and tested

| Control | Where | Test |
|---|---|---|
| Fail-closed config: `production`/`staging` refuse to start without API keys, with wildcard CORS, or with `LLM_AGENT` lacking a key | `config.py` | `test_config.py` |
| API-key auth; only SHA-256 digests configured; constant-time compare over all keys; `Authorization: Bearer` or `X-API-Key` | `security.py` | `test_api_security.py` |
| RBAC `viewer < operator < approver` enforced per route | `security.py`, `main.py` | roles test, mutation-checked |
| Identity from the credential, never the body (`approved_by` in the request is ignored) | `main.py` | `test_actor_in_audit_trail…` |
| Optional four-eyes (approver ≠ creator and ≠ investigator); default on in production-like envs | `services/remediation.py` | `test_four_eyes…` (service + HTTP) |
| Failed-auth throttling (10/min/IP), per-principal rate limit with `Retry-After`, request-body cap (413) | `security.py` | `test_repeated_failed…`, `test_rate_limit…`, `test_request_body_limit…` |
| Security headers incl. CSP, `X-Frame-Options`, `nosniff`, `no-referrer`, HSTS in production-like envs; `Cache-Control: no-store` on API | `security.py` | `test_security_headers…` |
| Docs/OpenAPI and demo simulators disabled in production-like envs | `main.py` | `test_production_like_config…` |
| Secrets/PII redaction (bearer/JWT/API keys/AWS keys/emails/Luhn-valid cards/private keys) at ingest **and** before model submission; redaction *counts* (not values) are audited | `redaction.py` | `test_redaction.py`, `test_ingest.py`, `test_secrets_never_reach_the_model` |
| Telemetry treated as untrusted: instruction-like records excluded from rule matching and surfaced as warnings; single forged signal cannot produce a diagnosis | `agent/diagnosis.py` | injection cases in `heldout`, `test_rules_engine.py` |
| LLM planner: 5 read-only tools, allowlist, once each, ≤6 calls, ≤7 turns, args re-validated, outputs wrapped as untrusted, rejected calls recorded and warned, retries + circuit breaker, outage → deterministic fallback | `agent/llm_*.py` | `test_llm_planner_security.py` (scripted hostile model) |
| Policy-as-code on every remediation, **re-evaluated at approval** (a tampered stored proposal is blocked) | `services/policy.py` | `test_policy_and_remediation.py` |
| Atomic approval (compare-and-swap) — exactly one winner under concurrency; stale proposals superseded on re-investigation | `db.py` | CAS unit test + 8-thread test, mutation-checked |
| Append-only audit via SQL triggers **plus** SHA-256 hash chain; `/api/audit/verify` detects edits, mid-chain deletes, reordering even if triggers are bypassed | `db.py` | `test_db.py` |
| Strict input validation (`extra=forbid`, bounded sizes/depth, ISO timestamps, idempotency-key charset); OTLP adapter tolerates malformed input | `models.py`, `services/otlp.py` | `test_ingest.py` |
| Errors never leak internals; every request gets a correlation ID | `main.py` | `test_unexpected_errors…` |
| Container: non-root, read-only root FS, all capabilities dropped, `no-new-privileges`, loopback-only port in compose | `Dockerfile`, `docker-compose.yml` | built and smoke-tested in CI (not runnable in the authoring sandbox) |
| Dependency scanning (`pip-audit`) and Dependabot | `.github/` | CI |

## Not implemented — required before wider exposure

| Gap | Why it matters | Suggested fix |
|---|---|---|
| **Single shared key per person, no SSO/OIDC, no key rotation/expiry UI** | Static bearer keys leak and live forever | OIDC + short-lived tokens; rotation via config reload |
| **Audit tail truncation is undetectable** unless the head hash is anchored elsewhere | An attacker with DB write access can drop the newest events | Periodically export `head_hash` (from `/api/audit/verify`) to an external append-only store |
| **No tenant isolation** | Incident IDs are not authorisation boundaries across customers | Tenant ID on every row + scoped queries |
| **SQLite, one connection, in-memory rate limiter** | Not HA; limiter is per process | PostgreSQL adapter; shared limiter at the edge |
| **Redaction is pattern-based** | Novel secret formats pass through | Allow-list structured fields; entropy detector; ingestion-time schema contracts |
| **Instruction-like text detection is heuristic** | Flagging is advisory; the real defence is structural (read-only tools, rules decide, human approves) | Keep it that way — do not add model-driven autonomy without a new threat model |
| **No real executor** | Simulation proves policy/flow, not real-world safety | If ever added: disposable, network-less sandbox; signed approvals; multi-party quorum |
| **No TLS termination** | HSTS is sent but TLS is not handled in-process | Terminate TLS at a reverse proxy; run uvicorn with `--proxy-headers` |
| **No CSRF protection** | Not needed for bearer-header auth; becomes necessary if cookie sessions are added | SameSite cookies + CSRF tokens |
| **Dashboard stores the API key in `sessionStorage`** | XSS would expose it (mitigated by CSP + output escaping) | Move to OIDC with HttpOnly cookies |

## Model-safety contract

The LLM can (1) choose the order/subset of five read-only diagnostic tools and (2) emit advisory text. It cannot set the root cause, create or approve
remediation, call any other function, or see unredacted telemetry. Tool results are wrapped as untrusted telemetry and size-limited. These properties are
enforced in code and exercised against a scripted model that tries to call `run_shell`, `approve_remediation`, floods tool calls, returns malformed
arguments, and embeds instructions in telemetry. A *real* model's behaviour is not evaluated here.

## Reporting

This is a portfolio project; open an issue for non-sensitive findings.
