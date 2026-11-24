# ADR 0002: Declarative weighted rules with explicit abstention

- **Status:** Accepted
- **Date:** 2026-11-24
- **Supersedes:** the hand-coded `if` chain in v1 `diagnosis.py`

## Context

v1 hardcoded exact metric names, exact log codes and fixed confidence constants (0.97, 0.93, …). That was brittle (any renamed metric broke it),
untestable beyond five fixtures, and its "confidence" values were invented rather than derived.

## Decision

Describe each root cause as data: weighted **signals** (predicate + kind + weight + "what to collect" hint). The engine:

1. normalises scales/units and matches **name patterns**, preferring the metric's own alert threshold over defaults;
2. scores `matched weight / total weight`;
3. makes a cause **eligible** only with an anchor signal, score ≥ 0.6 and ≥ 2 independent telemetry kinds;
4. **abstains** (`unknown`) when nothing is eligible or when two eligible causes are within 0.15;
5. reports `confidence` as an *evidence-coverage score*, discounted by a competing hypothesis — and measures its calibration instead of asserting it.

Instruction-like records are excluded from matching (fail closed) and reported as warnings.

## Alternatives considered

- **ML/LLM classifier.** Higher potential recall on unseen wording, but not debuggable, needs labelled data we do not have, costs money per run, and is
  easier to manipulate through log content. Kept as an *optional advisory* layer only.
- **Single-signal triggers.** Simpler, but trivially forgeable and noisy; rejected in favour of cross-kind corroboration.
- **Always pick the top-scoring cause.** Higher coverage, but the evaluation shows it would convert ambiguous multi-fault/causal-chain cases into confident wrong answers.

## Consequences

- (+) New causes are additive and reviewable; every output cites evidence IDs and states what is missing.
- (+) Wrong-diagnosis rate is the headline safety metric and is gated in CI.
- (−) Coverage is lower than a forced-choice classifier (72% on our sets). That is a deliberate trade.
- (−) Vocabulary is regex-based: on realistic stacks the author had not considered, only ~50% was recognised on first contact (see docs/EVALUATION.md).
- (−) Cannot separate cause from symptom (e.g. slow dependency → saturated pool); it abstains instead.
