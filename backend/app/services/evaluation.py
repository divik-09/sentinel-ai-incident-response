"""Offline evaluation harness.

Two splits are evaluated through the *production* investigation path (ingest -> tools -> rules -> proposal):

* ``dev``     the 5 bundled scenarios the rules were originally written against (regression).
* ``heldout`` 36 additional cases with renamed services, different units/scales, noise, missing data,
              novel faults, multi-fault/causal-chain ambiguity, prompt-injection text and secrets.

Honesty notes (also in docs/EVALUATION.md): both splits are synthetic and were authored by the rule author, and the
held-out split was run during development, so results are a regression signal, **not** an unbiased estimate of
accuracy on real incidents.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..agent.rules import RULESET_VERSION
from ..agent.runtime import InvestigationAgent
from ..config import DATA_DIR
from ..db import Database
from ..models import IncidentMeta
from ..scenarios import ScenarioRegistry
from .incidents import IncidentService
from .runbooks import RunbookRetriever

_EVIDENCE_INDEX = re.compile(r"-(\d{3})$")
ECE_BINS = 5
UNKNOWN = "unknown"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round((pct / 100) * (len(ordered) - 1))))
    return round(ordered[k], 2)


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure metric computation over per-case results (unit-tested against hand-computed values)."""
    total = len(results)
    if not total:
        return {"total_cases": 0}
    correct = sum(1 for r in results if r["passed"])
    labels = sorted({r["expected"] for r in results} | {r["predicted"] for r in results})
    expected_labels = {r["expected"] for r in results}

    per_class: list[dict[str, Any]] = []
    f1_values: list[float] = []
    for label in labels:
        tp = sum(1 for r in results if r["expected"] == label and r["predicted"] == label)
        fp = sum(1 for r in results if r["expected"] != label and r["predicted"] == label)
        fn = sum(1 for r in results if r["expected"] == label and r["predicted"] != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        support = tp + fn
        per_class.append({"label": label, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "support": support})
        if label in expected_labels:
            f1_values.append(f1)

    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in results:
        confusion[r["expected"]][r["predicted"]] += 1

    diagnosed = [r for r in results if r["predicted"] != UNKNOWN]
    wrong_diagnoses = [r for r in diagnosed if not r["passed"]]
    expected_unknown = [r for r in results if r["expected"] == UNKNOWN]
    predicted_unknown = [r for r in results if r["predicted"] == UNKNOWN]

    # calibration of the evidence score over diagnosed predictions
    scored = [r for r in diagnosed if r.get("confidence") is not None]
    brier = round(sum((r["confidence"] - (1.0 if r["passed"] else 0.0)) ** 2 for r in scored) / len(scored), 4) if scored else None
    bins: list[dict[str, Any]] = []
    ece = 0.0
    for i in range(ECE_BINS):
        lo, hi = i / ECE_BINS, (i + 1) / ECE_BINS
        members = [r for r in scored if lo <= r["confidence"] < hi or (i == ECE_BINS - 1 and r["confidence"] == 1.0)]
        if members:
            conf = sum(r["confidence"] for r in members) / len(members)
            acc = sum(1 for r in members if r["passed"]) / len(members)
            ece += abs(acc - conf) * len(members) / len(scored)
            bins.append({"range": f"{lo:.1f}-{hi:.1f}", "n": len(members), "mean_confidence": round(conf, 3), "accuracy": round(acc, 3)})

    # evidence quality (only where gold annotations exist and the label was right)
    ev_p: list[float] = []
    ev_r: list[float] = []
    for r in results:
        if r["passed"] and r["predicted"] != UNKNOWN and r.get("gold_evidence"):
            cited, gold = set(r["cited_indices"]), set(r["gold_evidence"])
            ev_p.append(len(cited & gold) / len(cited) if cited else 0.0)
            ev_r.append(len(cited & gold) / len(gold))

    by_tag: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "correct": 0})
    for r in results:
        for tag in r.get("tags", []):
            by_tag[tag]["n"] += 1
            by_tag[tag]["correct"] += 1 if r["passed"] else 0

    durations = [r["duration_ms"] for r in results]
    return {
        "total_cases": total,
        "correct": correct,
        "accuracy": round(correct / total, 4),
        "macro_f1": round(sum(f1_values) / len(f1_values), 4) if f1_values else 0.0,
        "coverage": round(len(diagnosed) / total, 4),
        "selective_accuracy": round((len(diagnosed) - len(wrong_diagnoses)) / len(diagnosed), 4) if diagnosed else None,
        "wrong_diagnosis_count": len(wrong_diagnoses),
        "wrong_diagnosis_rate": round(len(wrong_diagnoses) / len(diagnosed), 4) if diagnosed else 0.0,
        "abstain_precision": round(sum(1 for r in predicted_unknown if r["expected"] == UNKNOWN) / len(predicted_unknown), 4) if predicted_unknown else None,
        "abstain_recall": round(sum(1 for r in expected_unknown if r["predicted"] == UNKNOWN) / len(expected_unknown), 4) if expected_unknown else None,
        "mean_evidence_score": round(sum(r["confidence"] for r in scored) / len(scored), 4) if scored else None,
        "brier_score": brier,
        "expected_calibration_error": round(ece, 4) if scored else None,
        "reliability_bins": bins,
        "evidence_precision": round(sum(ev_p) / len(ev_p), 4) if ev_p else None,
        "evidence_recall": round(sum(ev_r) / len(ev_r), 4) if ev_r else None,
        "mean_evidence_count": round(sum(r["evidence_count"] for r in results) / total, 2),
        "latency_ms": {"p50": _percentile(durations, 50), "p95": _percentile(durations, 95), "max": round(max(durations), 2)},
        "per_class": per_class,
        "confusion": {k: dict(v) for k, v in confusion.items()},
        "by_tag": {k: {**v, "accuracy": round(v["correct"] / v["n"], 4)} for k, v in sorted(by_tag.items())},
    }


class EvaluationService:
    def __init__(self, scenarios: ScenarioRegistry, runbooks: RunbookRetriever, heldout_path: Path | None = None, probe_path: Path | None = None):
        self.scenarios = scenarios
        self.runbooks = runbooks
        self.heldout_path = heldout_path or DATA_DIR / "eval" / "heldout.json"
        self.probe_path = probe_path or DATA_DIR / "eval" / "probe.json"

    def _load_file(self, path: Path, split: str) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        return [
            {
                "id": c["id"],
                "split": split,
                "tags": c.get("tags", []),
                "expected": c["expected_root_cause"],
                "gold_evidence": c.get("gold_evidence", []),
                "meta": {k: c[k] for k in ("title", "service", "severity", "summary")},
                "telemetry": c["telemetry"],
            }
            for c in json.loads(path.read_text(encoding="utf-8"))
        ]

    def load_cases(self, split: str = "all") -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = []
        if split in ("dev", "all"):
            for s in self.scenarios.all():
                cases.append(
                    {
                        "id": s["id"],
                        "split": "dev",
                        "tags": ["dev_fixture"],
                        "expected": s["expected_root_cause"],
                        "gold_evidence": [],
                        "meta": {k: s[k] for k in ("title", "service", "severity", "summary")},
                        "telemetry": s["telemetry"],
                    }
                )
        if split in ("heldout", "all"):
            cases.extend(self._load_file(self.heldout_path, "heldout"))
        if split in ("probe", "all"):
            cases.extend(self._load_file(self.probe_path, "probe"))
        return cases

    def dataset_fingerprint(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.scenarios.path.read_bytes())
        for path in (self.heldout_path, self.probe_path):
            if path.exists():
                digest.update(path.read_bytes())
        return digest.hexdigest()[:16]

    def _run_case(self, case: dict[str, Any], temp_dir: str) -> dict[str, Any]:
        db = Database(str(Path(temp_dir) / f"{case['split']}-{case['id']}.db"))
        started = time.perf_counter()
        try:
            meta = IncidentMeta(**case["meta"])
            incident = IncidentService(db, self.scenarios).ingest(meta, case["telemetry"], actor="evaluation", source="evaluation")
            output = InvestigationAgent(db, self.runbooks).investigate(incident["id"], actor="evaluation")
            diagnosis = output["incident"].get("diagnosis", {})
            predicted = output["incident"].get("root_cause") or UNKNOWN
            ids = diagnosis.get("evidence_ids", [])
            return {
                "scenario_id": case["id"],
                "split": case["split"],
                "tags": case["tags"],
                "expected": case["expected"],
                "predicted": predicted,
                "passed": predicted == case["expected"],
                "confidence": output["incident"].get("confidence"),
                "evidence_count": diagnosis.get("evidence_count", 0),
                "abstain_reason": diagnosis.get("abstain_reason"),
                "warnings": [w["type"] for w in diagnosis.get("warnings", [])],
                "gold_evidence": case["gold_evidence"],
                "cited_indices": [int(m.group(1)) for i in ids if (m := _EVIDENCE_INDEX.search(i))],
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        finally:
            db.close()

    def run(self, split: str = "all") -> dict[str, Any]:
        started = time.perf_counter()
        cases = self.load_cases(split)
        with tempfile.TemporaryDirectory(prefix="sentinel-eval-") as temp_dir:
            results = [self._run_case(c, temp_dir) for c in cases]
        metrics = compute_metrics(results)
        by_split = {name: compute_metrics([r for r in results if r["split"] == name]) for name in sorted({r["split"] for r in results})}
        slim = [{k: v for k, v in r.items() if k not in {"gold_evidence", "cited_indices"}} for r in results]
        return {
            "run_id": uuid.uuid4().hex,
            "split": split,
            "ruleset_version": RULESET_VERSION,
            "dataset_fingerprint": self.dataset_fingerprint(),
            **metrics,
            "by_split": {
                k: {
                    m: v
                    for m, v in val.items()
                    if m in {"total_cases", "correct", "accuracy", "macro_f1", "coverage", "wrong_diagnosis_rate", "abstain_recall"}
                }
                for k, val in by_split.items()
            },
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "cases": slim,
            "note": (
                "Synthetic, author-written cases that were used during development. This is a regression and robustness signal, "
                "not a claim of accuracy on real production incidents. See docs/EVALUATION.md for limitations."
            ),
        }


BASELINE_METRICS_HIGHER_IS_BETTER = ("accuracy", "macro_f1", "coverage")
BASELINE_METRICS_LOWER_IS_BETTER = ("wrong_diagnosis_rate",)


def check_against_baseline(result: dict[str, Any], baseline: dict[str, Any], tolerance: float = 0.0) -> list[str]:
    """Return human-readable regressions versus a stored baseline (used as a CI gate)."""
    problems: list[str] = []
    if baseline.get("dataset_fingerprint") and baseline["dataset_fingerprint"] != result.get("dataset_fingerprint"):
        problems.append("dataset changed since the baseline was recorded; re-record it deliberately with --write-baseline")
    for split, base in baseline.get("by_split", {}).items():
        current = result.get("by_split", {}).get(split)
        if current is None:
            problems.append(f"split '{split}' missing from current run")
            continue
        for metric in BASELINE_METRICS_HIGHER_IS_BETTER:
            if metric in base and current.get(metric, 0) < base[metric] - tolerance:
                problems.append(f"{split}.{metric} regressed: {current.get(metric)} < baseline {base[metric]}")
        for metric in BASELINE_METRICS_LOWER_IS_BETTER:
            if metric in base and current.get(metric, 0) > base[metric] + tolerance:
                problems.append(f"{split}.{metric} regressed: {current.get(metric)} > baseline {base[metric]}")
    return problems
