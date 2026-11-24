#!/usr/bin/env bash
# End-to-end smoke test against a running instance.
#   ./scripts/smoke_test.sh [base_url]            # auth disabled (development)
#   SENTINEL_API_KEY=... ./scripts/smoke_test.sh  # auth enabled (needs an approver/operator key)
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
python - "$BASE_URL" <<'PY'
import json, os, sys, urllib.request

base = sys.argv[1]
key = os.environ.get("SENTINEL_API_KEY")

def request(path, method="GET", body=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())

assert request("/api/health")["status"] == "ok"
assert request("/api/ready")["status"] == "ready"
created = request("/api/incidents/ingest", "POST", {
    "external_id": "smoke-test", "title": "Smoke: pool exhaustion", "service": "smoke", "severity": "low", "summary": "smoke test",
    "telemetry": [
        {"kind": "metric", "service": "smoke", "payload": {"name": "db_pool_utilization", "value": 0.99, "unit": "ratio", "threshold": 0.85}},
        {"kind": "log", "service": "smoke", "payload": {"level": "ERROR", "code": "DB_POOL_TIMEOUT", "message": "Timed out waiting to acquire a database connection"}},
    ],
})
result = request(f"/api/incidents/{created['id']}/investigate", "POST", {})
cause = result["incident"]["root_cause"]
assert cause == "database_connection_pool_exhaustion", cause
assert request("/api/audit/verify")["valid"] is True
print(f"smoke test: PASS (diagnosis={cause}, evidence_score={result['incident']['confidence']})")
PY
