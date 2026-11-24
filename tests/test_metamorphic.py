"""Metamorphic / property tests: invariants that must hold regardless of labels.

These do not depend on the author's expected labels, so they are a less circular check than accuracy on fixtures.
"""

from __future__ import annotations

import copy
import random

import pytest

from backend.app.agent.diagnosis import diagnose
from tests.helpers import load_cases, to_tool_results

POSITIVE = [c for split in ("dev", "heldout") for c in load_cases(split) if c["expected"] != "unknown"]
UNKNOWN = [c for split in ("dev", "heldout") for c in load_cases(split) if c["expected"] == "unknown"]
ids = [c["id"] for c in POSITIVE]


def predict(telemetry):
    return diagnose(to_tool_results(telemetry))["root_cause"]


def rescale_units(telemetry):
    out = copy.deepcopy(telemetry)
    for rec in out:
        p = rec["payload"]
        if rec["kind"] != "metric":
            continue
        if p.get("unit") == "ratio":
            p["value"] *= 100
            p["unit"] = "percent"
            if "threshold" in p:
                p["threshold"] *= 100
        elif p.get("unit") == "ms":
            p["value"] /= 1000
            p["unit"] = "s"
            if "threshold" in p:
                p["threshold"] /= 1000
    return out


def rename_services(telemetry):
    out = copy.deepcopy(telemetry)
    for rec in out:
        rec["service"] = "svc-" + rec["service"][::-1]
    return out


def recase_codes(telemetry):
    out = copy.deepcopy(telemetry)
    for rec in out:
        if rec["kind"] == "log":
            rec["payload"]["code"] = rec["payload"]["code"].lower()
    return out


HEALTHY_NOISE = [
    {"kind": "metric", "service": "other", "payload": {"name": "request_p95_ms", "value": 90, "unit": "ms", "threshold": 500}},
    {"kind": "metric", "service": "other", "payload": {"name": "cpu_utilization", "value": 0.2, "unit": "ratio", "threshold": 0.85}},
    {"kind": "log", "service": "other", "payload": {"level": "INFO", "code": "REQUEST_OK", "message": "request completed"}},
    {"kind": "trace", "service": "other", "payload": {"operation": "GET /health", "duration_ms": 2, "status": "OK", "attributes": {}}},
]


@pytest.mark.parametrize("case", POSITIVE, ids=ids)
@pytest.mark.parametrize("transform", [rename_services, recase_codes, rescale_units], ids=lambda f: f.__name__)
def test_semantics_preserving_transforms_do_not_change_the_diagnosis(case, transform):
    baseline = predict(case["telemetry"])
    assert predict(transform(case["telemetry"])) == baseline


@pytest.mark.parametrize("case", POSITIVE, ids=ids)
def test_record_order_and_healthy_noise_do_not_change_the_diagnosis(case):
    baseline = predict(case["telemetry"])
    rng = random.Random(7)
    for _ in range(5):
        shuffled = copy.deepcopy(case["telemetry"]) + copy.deepcopy(HEALTHY_NOISE)
        rng.shuffle(shuffled)
        assert predict(shuffled) == baseline


@pytest.mark.parametrize("case", POSITIVE, ids=ids)
def test_removing_evidence_never_flips_to_a_different_cause(case):
    """Safety property: deleting telemetry may turn a diagnosis into an abstention, never into a *different* cause."""
    rng = random.Random(1234)
    for _ in range(30):
        keep = [r for r in case["telemetry"] if rng.random() < 0.6]
        assert predict(keep) in {case["expected"], "unknown"}


@pytest.mark.parametrize("case", UNKNOWN, ids=[c["id"] for c in UNKNOWN])
def test_healthy_noise_never_creates_a_diagnosis_from_nothing(case):
    base = predict(case["telemetry"])
    assert predict(case["telemetry"] + HEALTHY_NOISE) == base


def test_random_subsets_of_all_cases_never_produce_confident_wrong_answers_beyond_the_known_set():
    """Mix records from *different* incidents: any diagnosis must be one that is actually supported by its own signals."""
    rng = random.Random(99)
    pool = [r for c in POSITIVE for r in c["telemetry"]]
    for _ in range(300):
        sample = rng.sample(pool, k=rng.randint(1, 10))
        result = diagnose(to_tool_results(sample))
        if result["root_cause"] != "unknown":
            assert result["evidence_count"] >= 2 and result["confidence"] is not None
            kinds_by_id = {f"ev-test-{i:03d}": rec["kind"] for i, rec in enumerate(sample, start=1)}
            assert len({kinds_by_id[e] for e in result["evidence_ids"]}) >= 2
