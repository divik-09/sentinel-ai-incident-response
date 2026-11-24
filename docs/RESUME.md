# Using this project on a resume (and defending it)

Everything below is true of this repository as shipped. If you change the code, re-check the numbers (`make ci`).

## Resume bullets (pick 3–4; keep the numbers accurate)

**Backend / platform focus**
- Built a FastAPI incident-investigation service with API-key RBAC, credential-derived audit identity, four-eyes approval, rate limiting, and a **SHA-256 hash-chained, trigger-protected audit log** with a verification endpoint; atomic compare-and-swap approvals proven under 8-thread contention.
- Added versioned SQLite migrations, a validated ingestion API (idempotency keys, size/depth limits, secret/PII redaction) and an OTLP/JSON adapter; shipped structured JSON logging, request correlation, Prometheus metrics, readiness probes, and a hardened non-root container.
- Raised the test suite from 14 to **347 tests (94% branch coverage)** with metamorphic/property tests; mutation-checked 8 security-critical controls; CI runs ruff, mypy, pip-audit, a coverage gate and an evaluation-regression gate.

**AI / reliability focus**
- Designed an evidence-grounded diagnosis engine (declarative weighted rules, unit/scale normalisation, cross-source corroboration) that **abstains** on thin or conflicting evidence: **0 wrong diagnoses across 53 synthetic cases** at 72% coverage, reported alongside abstention precision/recall and calibration error.
- Hardened an optional LLM tool-calling planner (read-only allowlist, call budgets, untrusted-content envelope, retries + circuit breaker, deterministic fallback) and tested it against a scripted hostile model that attempts unauthorised tool calls and prompt injection via telemetry.
- Stress-tested the rules on realistic stack vocabulary: **6/12 on first contact** (all misses were safe abstentions), then widened coverage and documented the remaining limitation.

**Security focus**
- Implemented policy-as-code for remediation (action allowlist, numeric bounds, additive-only migrations) re-evaluated at approval time, with drift detection, read-back verification and rollback in a sandbox simulator.
- Treated telemetry as untrusted: instruction-like log text is excluded from rule matching and surfaced as a warning; a single forged signal cannot create a diagnosis.

## Claims to avoid (they are not true, and an interviewer can check)

| Don't say | Why |
|---|---|
| "AI-powered root-cause analysis" | The verdict is a rule engine. The LLM is optional and can't decide it. Say "evidence-scoring rule engine with an optional LLM tool-planner". |
| "100% accuracy" / "98% accuracy" | Synthetic, author-written data; held-out split was used in development. Say "0 wrong diagnoses on 53 synthetic cases (regression suite)". |
| "Production-ready" / "deployed" | It is production-*oriented* (fail-closed config, RBAC, observability, tested controls) but single-node, never run against real traffic, with documented gaps in SECURITY.md. |
| "Autonomous remediation" / "auto-fixes incidents" | Nothing real is changed; a human approves a **sandbox simulation**. |
| "Calibrated confidence" | It's an evidence-coverage score; ECE is 0.167 (under-confident). |
| "Prompt-injection proof" | It is *structurally* constrained and tested against a **scripted** model; no real-model red-teaming was done. |
| "Docker/Kubernetes ready" | The Dockerfile/compose/CI job exist but were not executed in the authoring environment — run `docker compose up --build` and the smoke test once before listing Docker. |
| "Supports OpenTelemetry" | It accepts an OTLP/**JSON subset** (spans, logs, gauge/sum metrics). No gRPC/protobuf receiver. |

## 60-second pitch

> "Sentinel investigates incidents from logs, metrics, traces and deployments. The interesting part is what it refuses to do: it only names a root cause when
> independent kinds of telemetry agree, it abstains when they don't, and it cites the evidence either way. Remediation is policy-checked, needs an
> authenticated approver, and runs only in a simulator with rollback, and every step goes into a hash-chained audit log. I measured it on synthetic
> cases — zero wrong diagnoses, 72% coverage — and I'm upfront that the author-written data isn't evidence about real incidents; on realistic log
> vocabulary I hadn't designed for, it first recognised about half, and it failed safe by abstaining."

## Questions you should expect — and honest answers

**"Is this actually AI?"** The diagnosis is a transparent rule engine on purpose: debuggable, free, cites evidence, can abstain. The LLM is an optional planner/reviewer
behind a read-only allowlist. I can show where each boundary is enforced and the tests that attack it.

**"How did you evaluate it?"** Three synthetic splits (5 dev, 36 held-out, 12 probe) through the production path, reporting wrong-diagnosis rate, coverage, abstention
precision/recall, Brier/ECE and evidence precision/recall, plus metamorphic tests that don't depend on my labels. Limitation: I wrote the rules *and* the cases.
The probe set's first run (6/12) is the number I trust most for generalisation.

**"Why abstain instead of guessing?"** A confident wrong root cause is worse than "I don't know, collect X". The evaluation shows forced-choice would have mislabelled
multi-fault and causal-chain cases. The cost is 72% coverage.

**"What's the weakest part?"** (1) Regex vocabulary coverage; (2) it can't separate cause from symptom; (3) single-node SQLite and in-process rate limiting;
(4) static API keys instead of SSO; (5) audit tail-truncation needs an external anchor; (6) no real incident data.

**"What did the tests find?"** Examples you can cite: a malformed OTLP data point caused a 500 (fixed + regression test); `as_ratio` treated raw byte counts as a ratio (fixed);
the first concurrency test passed even with the compare-and-swap disabled, so I added a direct primitive test (mutation check caught it).

**"What would you do next?"** PostgreSQL adapter; OIDC; external anchoring of the audit head; a tiered "low-confidence hypothesis" output; incident post-mortem-derived test
cases from someone other than the rule author; calibrating the score on a larger split; real executor only inside a network-less disposable sandbox.

## Where to point in the code

| Topic | File |
|---|---|
| Rule catalogue & normalisation | `backend/app/agent/rules.py` |
| Abstention & injection exclusion | `backend/app/agent/diagnosis.py` |
| Hostile-model tests | `tests/test_llm_planner_security.py` |
| Hash chain & CAS | `backend/app/db.py`, `tests/test_db.py` |
| Policy / simulation / rollback | `backend/app/services/policy.py`, `services/remediation.py` |
| Evaluation & metrics | `backend/app/services/evaluation.py`, `scripts/build_heldout.py` |
| Property tests | `tests/test_metamorphic.py` |
