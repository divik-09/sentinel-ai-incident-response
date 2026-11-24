# Evaluation

## What this measures — and what it does not

The harness runs each case through the **production path** (ingest → redaction → tools → rules → proposal → policy) in an isolated temporary SQLite database
and compares the result with the case's expected label.

It does **not** measure accuracy on real incidents. All data is synthetic. **The rules and the held-out/probe cases were written by the same person**, and
the held-out split was run repeatedly during development, so a high score here mostly says "the rules cover what their author imagined". The value of
this suite is (a) catching regressions, (b) forcing the system to be judged on *abstention and wrong-diagnosis rate*, not just accuracy, and
(c) documenting known failure modes.

## Splits

| Split | Cases | Origin | Purpose |
|---|---|---|---|
| `dev` | 5 | `scenarios.json` — the fixtures the rules were first written against | regression |
| `heldout` | 36 | `scripts/build_heldout.py` → `eval/heldout.json` | renamed services, different units/scales, noise, missing data, novel faults, multi-fault / causal-chain ambiguity, prompt-injection text, secrets |
| `probe` | 12 | `scripts/build_heldout.py` → `eval/probe.json` | realistic vocabulary from common stacks (pgbouncer, SQLAlchemy, nginx, JVM, Node, Django, k8s) written *without* consulting the rule regexes |

Expected label `unknown` means "the correct behaviour is to abstain" (novel faults, conflicting causes, single-source or metric-only evidence, forged signals).
For cases like `cache-metrics-only` the true cause is a cache stampede, but the *policy* (≥2 independent telemetry kinds) says abstain; those cases are
tagged `missing_data`/`single_source` so they can be read separately.

## Current results (`ruleset 2.0.0`, dataset `7eee2c3b076efe78`)

| Metric | All (53) | dev (5) | heldout (36) | probe (12) |
|---|---|---|---|---|
| Accuracy (label == expected) | **0.981** (52/53) | 1.00 | 1.00 | 0.917 |
| Wrong-diagnosis rate (diagnosed ≠ expected) | **0.000** | 0.00 | 0.00 | 0.00 |
| Coverage (fraction diagnosed rather than abstained) | 0.717 | 1.00 | 0.639 | 0.833 |
| Abstention recall (expected `unknown` → abstained) | 1.00 | – | 1.00 | 1.00 |
| Abstention precision (abstained → was expected `unknown`) | 0.933 | | | |
| Macro-F1 | 0.979 | 1.00 | 1.00 | 0.889 |
| Evidence precision / recall (cited vs annotated, correct cases) | 1.00 / 0.98 | | | |
| Evidence-score Brier / ECE (5 bins) | 0.055 / 0.167 | | | |
| Latency per case (p50 / p95) | ~1.5 ms / ~2–4 ms | | | |

Reading these honestly:

- **The headline number is not 98%.** It is *zero wrong diagnoses across 53 cases*, achieved by abstaining when evidence is weak (coverage 72%).
  All 1 remaining miss is an abstention, never a mislabel.
- **The evidence score is under-confident, not calibrated.** ECE 0.167: 100% of diagnosed cases were right even in the 0.6–0.8 band. It is a coverage
  score (matched signal weight / total weight, discounted by a competing hypothesis), and the UI labels it "evidence score".
- With 53 hand-written cases, differences of a few points are noise.

## The probe set: what happened before the rules were widened

First run of the 12 probe cases, **before** any vocabulary was added: **6 / 12 correct, 0 wrong diagnoses** — all 6 misses were safe abstentions caused
by names the rules did not know (`pgbouncer_pools_cl_waiting`, `QueuePool limit … reached`, `redis_keyspace_hit_ratio`, `container_memory_working_set_bytes`,
`ETIMEDOUT`, `postgres_queries_per_second`).

I then widened the patterns for those stacks (and fixed a real bug found on the way: `as_ratio` treated a raw byte count with no limit as a utilisation
ratio). **After** that: 11 / 12. Because the fix was informed by the probe cases, the probe split is now a *development* set too — the post-fix number is not
an unbiased estimate. The honest takeaway is the first number: *vocabulary coverage outside the author's mental model is roughly 50%, and the failure mode is
abstention.*

### Known limitation kept on purpose

`probe-rails-undefined-column`: a lone `PG::UndefinedColumn … column users.preferences does not exist` log plus a generic 5xx metric. Sentinel abstains
because one log is not independent corroboration of a schema migration problem, and proposing a DDL change on that basis would be reckless. A tiered
"low-confidence hypothesis" output would surface it without enabling remediation — future work.

## Robustness checks that do not depend on the author's labels

`tests/test_metamorphic.py` (154 generated tests) asserts invariants for every positive case in `dev` + `heldout`:

- renaming services, re-casing log codes, and rescaling units (ratio↔percent, ms↔s) **never change** the diagnosis;
- shuffling record order and adding healthy noise **never change** the diagnosis;
- **randomly deleting 40% of the evidence 30× never flips the diagnosis to a *different* cause** (it may become `unknown`);
- mixing records from different incidents never yields a diagnosis lacking ≥2 independent telemetry kinds.

Security controls were additionally **mutation-checked**: eight deliberate breakages (LLM allowlist bypass, policy bound removal, CAS removal, audit-verify
skip, injection-exclusion off, RBAC check off, email redaction off, percent-normalisation off) are each caught by the suite.

## Running it

```bash
python scripts/run_evaluation.py --summary             # all splits
python scripts/run_evaluation.py --split probe
python scripts/run_evaluation.py --check               # CI gate versus docs/benchmark-baseline.json
python scripts/run_evaluation.py --write-baseline      # only after a deliberate, reviewed change
python scripts/build_heldout.py                        # regenerate the JSON datasets
```

The gate fails if any split's accuracy/macro-F1/coverage drops or its wrong-diagnosis rate rises, or if the dataset fingerprint changes without the baseline
being re-recorded.

## What would make this a real evaluation

1. Cases written by someone who has not seen the rules, ideally from **real, anonymised incident post-mortems**.
2. A frozen test split that is never used for rule changes; report results only on it.
3. Real telemetry (OTLP from instrumented services) with fault injection in a live environment.
4. Calibrating the evidence score (isotonic/Platt) on a split large enough to support it (hundreds of cases, not tens).
5. For the optional LLM planner: tool-selection efficiency and cost versus the deterministic order, on a held-out set.
