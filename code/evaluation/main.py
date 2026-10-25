"""Evaluation runner CLI.
Evaluates predictions against sample ground truth and prints accuracy reports.
"""
import sys
import argparse
from pathlib import Path

from code.config import Config
from code.evaluation.evaluator import Evaluator


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists Evaluation Benchmark")
    default_actual = Path("sample_output_predictions.csv") if Path("sample_output_predictions.csv").exists() else Path("output.csv")
    parser.add_argument(
        "--actual",
        type=Path,
        default=default_actual,
        help="Path to predicted output.csv"
    )
    parser.add_argument(
        "--expected",
        type=Path,
        default=Path("dataset/sample_output.csv"),
        help="Path to ground truth expected sample_output.csv"
    )
    args = parser.parse_args()

    if not args.actual.exists():
        print(f"[!] Actual output file not found: {args.actual}")
        return 1
    if not args.expected.exists():
        print(f"[!] Ground truth file not found: {args.expected}")
        return 1

    print(f"[*] Evaluating {args.actual} against {args.expected} ...")
    metrics = Evaluator.evaluate(args.actual, args.expected)

    print("=" * 60)
    print(" EVALUATION METRICS REPORT")
    print("=" * 60)
    print(f" Total Cases Evaluated   : {metrics.total_cases}")
    print(f" Status Matches          : {metrics.status_matches}/{metrics.total_cases}")
    print(f" Status Accuracy         : {metrics.status_accuracy * 100:.2f}%")
    print(f" Step Precision          : {metrics.step_precision * 100:.2f}%")
    print(f" Step Recall             : {metrics.step_recall * 100:.2f}%")
    print(f" Step F1 Score           : {metrics.step_f1 * 100:.2f}%")
    print(f" Exact Sequence Matches  : {metrics.exact_sequence_matches}/{metrics.total_cases}")
    print(f" Sequence Accuracy       : {metrics.sequence_accuracy * 100:.2f}%")
    print("-" * 60)
    print(" Field Accuracy Breakdown:")
    for fld, acc in metrics.field_accuracy.items():
        print(f"   {fld:<16} : {acc * 100:.2f}%")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
