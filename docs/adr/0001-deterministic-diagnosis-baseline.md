# ADR 0001: Keep deterministic diagnosis as the baseline

- **Status:** Accepted (implementation refined by [ADR 0002](0002-declarative-rules-and-abstention.md))
- **Date:** 2026-11-20

## Context

A portfolio incident-response agent needs to be inspectable and reproducible. A model-only diagnosis can be difficult to debug, expensive to run, and prone to overstate conclusions when telemetry is incomplete.

## Decision

Use deterministic multi-signal rules as the authoritative baseline. The investigation runtime still demonstrates agent orchestration through explicit tool calls. An optional LLM reviewer may provide an advisory second opinion, but it cannot change the root-cause label or execute actions.

## Consequences

- Benchmark results are deterministic and have no model API cost.
- Every diagnosis can cite concrete telemetry records.
- Novel incidents may return `unknown`; expanding the rule set and evaluation dataset is explicit work.
- The model-backed path is intentionally limited and should be expanded only behind the same tool allowlist and safety policy.
