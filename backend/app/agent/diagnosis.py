"""Evidence-scoring diagnosis engine.

Pipeline: normalise records -> exclude instruction-like (potentially adversarial) records ->
score each rule's weighted signals -> require an anchor + >=2 independent telemetry kinds ->
abstain on conflicting hypotheses -> emit a diagnosis that cites telemetry IDs.

``confidence`` is an **evidence-coverage score** (matched signal weight / total signal weight,
discounted when a competing hypothesis is also supported). It is *not* a calibrated probability.
Calibration on held-out data is measured and reported by the evaluation harness.
"""

from __future__ import annotations

from typing import Any

from ..redaction import looks_like_injection
from .rules import RULES, RULESET_VERSION, CauseRule, Record, num

CONFLICT_MARGIN = 0.15
MIN_INDEPENDENT_KINDS = 2
MAX_EVIDENCE_PER_SIGNAL = 3

CAUSE_LABELS = {rule.root_cause: rule.label for rule in RULES}
CAUSE_LABELS["unknown"] = "Insufficient evidence to identify a root cause"

TOOL_KINDS = {"query_metrics": "metric", "search_logs": "log", "inspect_traces": "trace", "deployment_history": "deployment"}


def _records(tool_results: dict[str, dict[str, Any]], tool: str) -> list[Record]:
    return list(tool_results.get(tool, {}).get("records", []))


def _texts(rec: Record) -> list[str]:
    out = [str(rec.get(k, "")) for k in ("message", "code", "operation", "changes", "version", "name")]
    attrs = rec.get("attributes")
    if isinstance(attrs, dict):
        out.extend(str(v) for v in attrs.values() if isinstance(v, str))
    return [t for t in out if t]


def is_instruction_like(rec: Record) -> bool:
    return any(looks_like_injection(t) for t in _texts(rec))


def _score_rule(rule: CauseRule, usable: list[Record]) -> dict[str, Any]:
    matched: dict[str, list[Record]] = {}
    for sig in rule.signals:
        hits = [r for r in usable if r.get("kind") == sig.kind and sig.match(r)]
        if hits:
            matched[sig.id] = hits
    weight = sum(s.weight for s in rule.signals if s.id in matched)
    kinds = {s.kind for s in rule.signals if s.id in matched}
    evidence_ids: list[str] = []
    for sig in rule.signals:
        for hit in matched.get(sig.id, [])[:MAX_EVIDENCE_PER_SIGNAL]:
            if hit.get("evidence_id") and hit["evidence_id"] not in evidence_ids:
                evidence_ids.append(hit["evidence_id"])
    score = round(weight / rule.total_weight, 4)
    anchored = any(a in matched for a in rule.anchors)
    return {
        "rule": rule,
        "matched": matched,
        "score": score,
        "kinds": kinds,
        "anchored": anchored,
        "eligible": anchored and score >= rule.min_score and len(kinds) >= MIN_INDEPENDENT_KINDS,
        "evidence_ids": evidence_ids,
    }


def diagnose(tool_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    all_records = [r for tool in TOOL_KINDS for r in _records(tool_results, tool)]
    excluded = [r for r in all_records if is_instruction_like(r)]
    excluded_ids = {r.get("evidence_id") for r in excluded}
    usable = [r for r in all_records if r.get("evidence_id") not in excluded_ids]

    scored = [_score_rule(rule, usable) for rule in RULES]
    partial = sorted((s for s in scored if s["matched"]), key=lambda s: (s["score"], len(s["evidence_ids"])), reverse=True)
    eligible = [s for s in partial if s["eligible"]]

    warnings: list[dict[str, Any]] = []
    if excluded:
        warnings.append(
            {
                "type": "instruction_like_telemetry",
                "message": f"{len(excluded)} telemetry record(s) contain instruction-like text. They were treated as untrusted data and excluded from rule matching.",
                "evidence_ids": [r["evidence_id"] for r in excluded if r.get("evidence_id")],
            }
        )

    abstain_reason: str | None = None
    if not eligible:
        abstain_reason = "insufficient_evidence"
    elif len(eligible) > 1 and eligible[0]["score"] - eligible[1]["score"] < CONFLICT_MARGIN:
        abstain_reason = "conflicting_hypotheses"

    alternatives = [{"root_cause": s["rule"].root_cause, "evidence_score": s["score"]} for s in partial]

    if abstain_reason is None:
        best = eligible[0]
        rule: CauseRule = best["rule"]
        runner = eligible[1]["score"] if len(eligible) > 1 else 0.0
        confidence = round(best["score"] * (1 - 0.5 * runner), 3)
        winner: dict[str, Any] = {
            "root_cause": rule.root_cause,
            "confidence": confidence,
            "evidence_score": best["score"],
            "signals": [s.description for s in rule.signals if s.id in best["matched"]],
            "matched_signal_ids": [s.id for s in rule.signals if s.id in best["matched"]],
            "missing_signals": [s.missing_hint for s in rule.signals if s.id not in best["matched"]],
            "evidence_ids": best["evidence_ids"],
            "alternative_hypotheses": [a for a in alternatives if a["root_cause"] != rule.root_cause],
            "abstain_reason": None,
        }
    else:
        top = partial[0] if partial else None
        if abstain_reason == "conflicting_hypotheses":
            names = ", ".join(s["rule"].root_cause for s in eligible[:3])
            signals = [f"Comparable evidence supports more than one cause ({names}); Sentinel will not pick one automatically."]
            ids = list(dict.fromkeys(i for s in eligible[:2] for i in s["evidence_ids"]))
            missing = ["a discriminating signal, e.g. which failure began first in the trace/deployment timeline"]
        else:
            signals = ["No diagnostic rule had enough independent evidence to support a root-cause claim."]
            ids = top["evidence_ids"] if top else list(dict.fromkeys(r["evidence_id"] for r in usable if r.get("evidence_id")))[:8]
            missing = (
                [s.missing_hint for s in top["rule"].signals if s.id not in top["matched"]]
                if top
                else ["metrics, logs and traces that correspond to a known failure pattern"]
            )
        winner = {
            "root_cause": "unknown",
            "confidence": None,
            "evidence_score": top["score"] if top else 0.0,
            "signals": signals,
            "matched_signal_ids": [],
            "missing_signals": missing,
            "evidence_ids": ids,
            "alternative_hypotheses": alternatives,
            "abstain_reason": abstain_reason,
        }

    winner["label"] = CAUSE_LABELS[winner["root_cause"]]
    winner["evidence_ids"] = [i for i in winner["evidence_ids"] if i]
    winner["evidence_count"] = len(winner["evidence_ids"])
    winner["warnings"] = warnings
    winner["ruleset_version"] = RULESET_VERSION
    winner["impact"] = _summarize_impact(_records(tool_results, "query_metrics"), _records(tool_results, "search_logs"))
    return winner


def _summarize_impact(metrics: list[Record], logs: list[Record]) -> str:
    by_name = {m.get("name"): m.get("value") for m in metrics}
    for name in ("http_5xx_rate", "error_rate"):
        value = num(by_name.get(name))
        if value is not None:
            pct = value if value > 1 else value * 100
            return f"HTTP error rate is {pct:.1f}% in the observed window."
    p95 = num(by_name.get("request_p95_ms"))
    if p95 is not None:
        return f"Observed request p95 latency is {by_name['request_p95_ms']} ms."
    if logs:
        return f"{len(logs)} error or warning log records were collected for this incident."
    return "Impact could not be quantified from the available telemetry."
