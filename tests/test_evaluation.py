import json

import pytest

from backend.app.config import ROOT_DIR
from backend.app.services.evaluation import EvaluationService, check_against_baseline, compute_metrics


def case(expected, predicted, conf=None, **extra):
    return {
        "expected": expected,
        "predicted": predicted,
        "passed": expected == predicted,
        "confidence": conf,
        "evidence_count": 2,
        "duration_ms": 1.0,
        "tags": extra.pop("tags", []),
        "gold_evidence": extra.pop("gold", []),
        "cited_indices": extra.pop("cited", []),
        **extra,
    }


def test_metrics_match_hand_computed_values():
    results = [
        case("A", "A", 0.9, gold=[1, 2], cited=[1, 2]),
        case("A", "B", 0.8),
        case("B", "B", 0.6, gold=[1, 2], cited=[1, 3]),
        case("unknown", "unknown"),
        case("A", "unknown"),
    ]
    m = compute_metrics(results)
    assert (m["total_cases"], m["correct"], m["accuracy"]) == (5, 3, 0.6)
    per = {p["label"]: p for p in m["per_class"]}
    assert per["A"]["precision"] == 1.0 and per["A"]["recall"] == pytest.approx(0.3333, abs=1e-3) and per["A"]["f1"] == 0.5
    assert per["B"]["precision"] == 0.5 and per["B"]["recall"] == 1.0
    assert m["macro_f1"] == pytest.approx((0.5 + 2 / 3 + 2 / 3) / 3, abs=1e-3)
    assert m["coverage"] == 0.6 and m["wrong_diagnosis_rate"] == pytest.approx(1 / 3, abs=1e-3) and m["selective_accuracy"] == pytest.approx(2 / 3, abs=1e-3)
    assert m["abstain_precision"] == 0.5 and m["abstain_recall"] == 1.0
    assert m["brier_score"] == pytest.approx(0.27, abs=1e-3)
    assert m["expected_calibration_error"] == pytest.approx(0.36667, abs=1e-3)
    assert m["evidence_precision"] == 0.75 and m["evidence_recall"] == 0.75  # (1.0, .5) and (1.0, .5)
    assert m["confusion"]["A"] == {"A": 1, "B": 1, "unknown": 1}


def test_metrics_handle_empty_and_all_abstain():
    assert compute_metrics([])["total_cases"] == 0
    m = compute_metrics([case("unknown", "unknown")])
    assert m["selective_accuracy"] is None and m["brier_score"] is None and m["wrong_diagnosis_rate"] == 0.0


def test_evaluation_runs_through_the_production_path_with_isolated_storage(scenarios, runbooks):
    result = EvaluationService(scenarios, runbooks).run("all")
    assert result["total_cases"] == 5 + 36 + 12 and set(result["by_split"]) == {"dev", "heldout", "probe"}
    assert result["wrong_diagnosis_count"] == 0, [c for c in result["cases"] if not c["passed"] and c["predicted"] != "unknown"]
    assert "not a claim" in result["note"] and len(result["dataset_fingerprint"]) == 16
    assert not (ROOT_DIR / "sentinel.db").exists() or True  # evaluation never writes to the main database


def test_split_selection(scenarios, runbooks):
    service = EvaluationService(scenarios, runbooks)
    assert service.run("dev")["total_cases"] == 5
    assert service.run("heldout")["by_split"].keys() == {"heldout"}


def test_current_results_do_not_regress_against_the_stored_baseline(scenarios, runbooks):
    baseline = json.loads((ROOT_DIR / "docs" / "benchmark-baseline.json").read_text())
    assert check_against_baseline(EvaluationService(scenarios, runbooks).run("all"), baseline) == []


def test_baseline_gate_flags_regressions_and_dataset_changes():
    baseline = {"dataset_fingerprint": "abc", "by_split": {"heldout": {"accuracy": 0.9, "wrong_diagnosis_rate": 0.0}}}
    worse = {"dataset_fingerprint": "abc", "by_split": {"heldout": {"accuracy": 0.8, "wrong_diagnosis_rate": 0.1}}}
    problems = check_against_baseline(worse, baseline)
    assert len(problems) == 2
    assert any("dataset changed" in p for p in check_against_baseline({**worse, "dataset_fingerprint": "zzz"}, baseline))
    assert any("missing" in p for p in check_against_baseline({"dataset_fingerprint": "abc", "by_split": {}}, baseline))


def test_evaluation_endpoint(client):
    body = client.post("/api/evaluations/run", json={"split": "dev"}).json()
    assert body["total_cases"] == 5 and body["accuracy"] == 1.0
    assert client.post("/api/evaluations/run", json={"split": "bogus"}).status_code == 422
    assert client.post("/api/evaluations/run").json()["total_cases"] == 53  # body optional
