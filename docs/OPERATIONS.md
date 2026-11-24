# Operations guide

## Run

```bash
make install && make run                                    # development, auth off, demo on
uvicorn backend.app.main:create_app --factory --host 0.0.0.0 --port 8000 --proxy-headers --no-access-log    # production-like
```

The app is a **factory** (`--factory`); nothing is created at import time.

## Configuration

See [`.env.example`](../.env.example). Highlights:

| Variable | Default | Notes |
|---|---|---|
| `SENTINEL_ENV` | `development` | `staging`/`production` refuse to start without `SENTINEL_API_KEYS`, reject `*` CORS, hide `/docs` + demo endpoints, enable HSTS + four-eyes |
| `SENTINEL_API_KEYS` | – | `name:role:sha256hex,…`; generate with `scripts/create_api_key.py` |
| `SENTINEL_AUTH_MODE` | `api_key` if keys set, else `disabled` | `disabled` is rejected in production-like envs |
| `SENTINEL_FOUR_EYES` | on in production-like | approver ≠ creator/investigator |
| `SENTINEL_RATE_LIMIT_PER_MINUTE` | 240 | per principal; 0 disables |
| `SENTINEL_MAX_BODY_BYTES` | 1 MiB | 413 above this |
| `SENTINEL_ENABLE_LLM_AGENT` / `_MODEL_SYNTHESIS` | false | require `OPENAI_API_KEY`; fall back automatically on failure |

## Endpoints for operators

| Endpoint | Use |
|---|---|
| `GET /api/health` | liveness (always cheap) |
| `GET /api/ready` | readiness: DB reachable **and** schema at the latest version (503 otherwise) |
| `GET /metrics` | Prometheus (viewer role): `sentinel_http_requests_total{method,route,status}`, `sentinel_http_request_duration_seconds`, `sentinel_investigations_total{root_cause,mode}`, `sentinel_investigation_duration_seconds`, `sentinel_remediation_decisions_total{decision}`, `sentinel_llm_requests_total{outcome}`, `sentinel_ingested_incidents_total{source}` |
| `GET /api/audit/verify` | recompute the audit hash chain; **alert if `valid` is false**; record `head_hash` externally to detect tail truncation |

Suggested alerts: `/api/ready` ≠ 200; audit `valid=false`; sustained 5xx ratio; `sentinel_llm_requests_total{outcome="breaker_open"}` rising;
`sentinel_remediation_decisions_total{decision="blocked_by_policy"}` spikes.

## Logs

JSON lines to stdout: `ts, level, logger, msg, request_id, method, path, route, status, duration_ms, principal`. Send `X-Request-ID` to correlate with
upstream traces; it is echoed back. Secrets are not logged (auth headers are never logged; telemetry is redacted before storage).

## Data & backups

SQLite in WAL mode at `SENTINEL_DATABASE_PATH` (Docker: `/data/sentinel.db` on the `sentinel-data` volume). Back up with `sqlite3 sentinel.db ".backup out.db"`
while running. Migrations run at startup and are forward-only; **take a backup before upgrading**. The audit log cannot be edited or deleted through
SQL (triggers), so "reset" means removing the whole database file.

## Scaling and failure modes

- **One process, one instance.** SQLite + in-memory limiter. Do not run replicas behind a load balancer until the DB and limiter are externalised.
- Investigations are synchronous and take milliseconds on the rule path; with the LLM planner they are bounded by `SENTINEL_LLM_TIMEOUT_SECONDS`
  × retries × ≤7 turns, and the circuit breaker (3 failures → 60 s open) caps the damage of an outage.
- If the model is down the system still produces the same diagnosis (the model never decides it).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Startup error `Refusing to start in 'production' without authentication` | Set `SENTINEL_API_KEYS` (see key script) |
| `401` from the dashboard | It prompts for a key once and keeps it in `sessionStorage` |
| `403 Four-eyes policy…` | A different approver must approve (not the creator/investigator) |
| `409 Configuration drift…` | The simulated config changed after the proposal; re-run the investigation |
| `503` on `/api/ready` | Schema not at latest version or DB unreachable; check logs |
| `/docs` is 404 | Intentional in production-like environments |

## Upgrade checklist

1. Back up the database. 2. Deploy the new image. 3. Wait for `/api/ready` = 200 (migrations applied). 4. Hit `/api/audit/verify`.
5. Run `python scripts/run_evaluation.py --check` in CI for any rule change; re-record the baseline only deliberately.
