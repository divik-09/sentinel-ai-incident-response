"""Run the offline evaluation.

python scripts/run_evaluation.py                 # all splits, JSON to stdout
python scripts/run_evaluation.py --split heldout --summary
python scripts/run_evaluation.py --check         # CI gate: fail on regression vs docs/benchmark-baseline.json
python scripts/run_evaluation.py --write-baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.scenarios import ScenarioRegistry
from backend.app.services.evaluation import EvaluationService, check_against_baseline
from backend.app.services.runbooks import RunbookRetriever

BASELINE = Path(__file__).resolve().parents[1] / "docs" / "benchmark-baseline.json"
KEYS = (
    "run_id",
    "split",
    "ruleset_version",
    "dataset_fingerprint",
    "total_cases",
    "correct",
    "accuracy",
    "macro_f1",
    "coverage",
    "selective_accuracy",
    "wrong_diagnosis_count",
    "wrong_diagnosis_rate",
    "abstain_precision",
    "abstain_recall",
    "brier_score",
    "expected_calibration_error",
    "evidence_precision",
    "evidence_recall",
    "latency_ms",
    "by_split",
    "by_tag",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--split", choices=["dev", "heldout", "probe", "all"], default="all")
    parser.add_argument("--summary", action="store_true", help="print metrics only (no per-case rows)")
    parser.add_argument("--check", action="store_true", help="exit 1 if results regress versus the stored baseline")
    parser.add_argument("--write-baseline", action="store_true", help="overwrite the stored baseline with this run")
    args = parser.parse_args()

    result = EvaluationService(ScenarioRegistry(), RunbookRetriever()).run("all" if (args.check or args.write_baseline) else args.split)

    if args.write_baseline:
        slim = {
            k: result[k]
            for k in (
                "ruleset_version",
                "dataset_fingerprint",
                "total_cases",
                "accuracy",
                "macro_f1",
                "coverage",
                "wrong_diagnosis_rate",
                "wrong_diagnosis_count",
                "abstain_precision",
                "abstain_recall",
                "brier_score",
                "expected_calibration_error",
                "by_split",
            )
        }
        slim["note"] = result["note"]
        BASELINE.write_text(json.dumps(slim, indent=2) + "\n", encoding="utf-8")
        print(f"baseline written to {BASELINE}")
        return 0

    if args.check:
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        problems = check_against_baseline(result, baseline)
        if problems:
            print("EVALUATION REGRESSION:\n  - " + "\n  - ".join(problems), file=sys.stderr)
            return 1
        print(
            f"evaluation OK: {result['correct']}/{result['total_cases']} correct, wrong-diagnosis rate {result['wrong_diagnosis_rate']}, no regression vs baseline"
        )
        return 0

    print(json.dumps({k: result[k] for k in KEYS} if args.summary else result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
