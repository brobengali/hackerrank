"""Ghost Data Still Exists — AI-Powered Deletion Audit Agent.
Main executable application entry point.

Implements the end-to-end deletion audit pipeline:
1. Load and validate input datasets and deletion rules.
2. Resolve identities across current and historical snapshots.
3. Cross-system investigation & event reconstruction up to audit_at.
4. Detect resurrection paths (data flows, restore risks).
5. Generate dependency-ordered remediation plans.
6. Enforce deterministic verification invariants via post-model safety gate.
7. Produce valid output.csv meeting all competition requirements.
8. Record auditable execution summary.
"""
import sys
from pathlib import Path

# Ensure repository root is on sys.path so direct invocation 'python code/main.py' works
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import argparse
import time
from typing import List, Dict, Any, Optional
import csv
import json

from code.config import Config
from code.models import DeletionCase, CaseAuditResult, DeletionStatus
from code.core.loader import DataLoader
from code.core.batch_processor import BatchAuditProcessor
from code.core.reporter import Reporter
from code.core.schema_validator import SchemaValidator
from code.core.logging_utils import get_logger, mask_email
from code.evaluation.evaluator import Evaluator

logger = get_logger("Main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ghost Data Still Exists -- AI-Powered Deletion Audit Agent"
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset"),
        help="Path to dataset directory containing deletion requests, rules, and evidence"
    )
    parser.add_argument(
        "--cases-file",
        type=Path,
        default=None,
        help="Path to specific deletion requests CSV (defaults to dataset/deletion_requests.csv)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output.csv"),
        help="Path where final output.csv will be written"
    )
    parser.add_argument(
        "--eval-samples",
        action="store_true",
        help="Run evaluation against sample_deletion_requests.csv and score against sample_output.csv"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of cases to process (useful for testing)"
    )
    return parser.parse_args()


def run_pipeline(
    dataset_dir: Path,
    cases_file: Optional[Path],
    output_path: Path,
    is_eval_samples: bool = False,
    limit: Optional[int] = None
) -> int:
    start_time = time.time()
    print("=" * 70)
    print(" HackerRank Orchestrate (October 2026) -- Ghost Data Still Exists")
    print(" AI-Powered Deletion Audit Agent Pipeline")
    print("=" * 70)

    # 1. Initialize configuration and validate dataset paths
    config = Config(dataset_dir=dataset_dir)
    print(f"[*] Validating repository dataset paths at: {config.dataset_dir} ...")
    try:
        config.validate_paths()
    except Exception as e:
        print(f"[!] Path validation failed: {e}")
        return 1

    # 2. Determine target input cases
    if is_eval_samples:
        target_cases_file = config.sample_requests_path
        ground_truth_path = config.sample_output_path
        print(f"[*] Running in SAMPLE EVALUATION mode: {target_cases_file}")
    else:
        target_cases_file = cases_file or config.deletion_requests_path
        ground_truth_path = None
        print(f"[*] Running in FULL AUDIT mode: {target_cases_file}")

    if not target_cases_file.exists():
        print(f"[!] Target requests file does not exist: {target_cases_file}")
        return 1

    # 3. Load target deletion cases
    print(f"[*] Loading deletion requests from: {target_cases_file} ...")
    loader = DataLoader()
    cases: List[DeletionCase] = loader.load_deletion_cases(target_cases_file)
    if limit and limit > 0:
        cases = cases[:limit]
        print(f"[*] Processing limited subset of {len(cases)} requests")
    else:
        print(f"[*] Loaded {len(cases)} requests to audit")

    # 4. Initialize Batch Audit Processor
    print("[*] Initializing BatchAuditProcessor and indexing cross-system evidence ...")
    init_start = time.time()
    processor = BatchAuditProcessor(config)
    print(f"[*] Subsystems initialized in {time.time() - init_start:.2f}s")

    # 5. Execute batch audit
    print(f"[*] Auditing {len(cases)} cases independently with fault isolation ...")
    audit_start = time.time()
    results, summary = processor.run_all(cases)
    audit_duration = time.time() - audit_start
    print(f"[*] Completed audit of {len(results)} cases in {audit_duration:.2f}s")

    # 6. Write final output CSV
    print(f"[*] Writing output CSV to: {output_path} ...")
    Reporter.write_output_csv(results, output_path)

    # 7. Validate generated output against competition contract
    print(f"[*] Validating output schema contracts for: {output_path} ...")
    expected_count = len(cases)
    is_valid, validation_errors = SchemaValidator.validate_output_csv(output_path, expected_count)
    if is_valid:
        print(f"[+] Output validation PASSED: Exactly {expected_count} valid, sorted rows.")
    else:
        print(f"[!] Output validation FAILED with {len(validation_errors)} errors:")
        for err in validation_errors[:5]:
            print(f"    - {err}")

    # 8. Display auditable execution summary
    print("\n" + "=" * 70)
    print(" AUDIT EXECUTION SUMMARY")
    print("=" * 70)
    print(f" Total Requests Processed : {summary['total_cases']}")
    print(f"   - COMPLETE Status       : {summary['complete_count']}")
    print(f"   - INCOMPLETE Status     : {summary['incomplete_count']}")
    print(f"   - NOT_APPLICABLE Status : {summary['not_applicable_count']}")
    print(f" Processing Failures      : {summary['failures_count']}")
    print(f" Total Elapsed Time       : {time.time() - start_time:.2f}s")

    # 9. Redacted sample output preview
    print("\n" + "-" * 70)
    print(" REDACTED SAMPLE PREVIEW (first 5 output rows)")
    print("-" * 70)
    sample_preview = results[:5]
    for r in sample_preview:
        step_summary = f"{len(r.steps)} steps" if r.steps else "no steps"
        print(f" Case ID: {r.case_id:<12} | Status: {r.status.value:<15} | Steps: {step_summary}")
        for s in r.steps[:2]:
            ev = f" (ev={s.evidence_id})" if s.evidence_id else ""
            print(f"    -> [{s.phase.value}] {s.system_id}:{s.resource_id} | {s.operation.value} -> {s.state.value}{ev}")
        if len(r.steps) > 2:
            print(f"    -> ... [{len(r.steps) - 2} more steps]")

    # 10. Sample evaluation scoring (if requested)
    if is_eval_samples and ground_truth_path and ground_truth_path.exists():
        print("\n" + "=" * 70)
        print(" SAMPLE EVALUATION BENCHMARK METRICS")
        print("=" * 70)
        metrics = Evaluator.evaluate(output_path, ground_truth_path)
        print(f" Status Accuracy          : {metrics.status_accuracy * 100:.2f}% ({metrics.status_matches}/{metrics.total_cases})")
        print(f" Step Precision           : {metrics.step_precision * 100:.2f}%")
        print(f" Step Recall              : {metrics.step_recall * 100:.2f}%")
        print(f" Step F1 Score            : {metrics.step_f1 * 100:.2f}%")
        print(f" Exact Sequence Accuracy  : {metrics.sequence_accuracy * 100:.2f}% ({metrics.exact_sequence_matches}/{metrics.total_cases})")
        print(" Field Accuracy Breakdown :")
        for fld, acc in metrics.field_accuracy.items():
            print(f"   - {fld:<14} : {acc * 100:.2f}%")

    print("\n" + "=" * 70)
    print(" Pipeline execution finished successfully.")
    print("=" * 70)
    return 0 if (is_valid and summary["failures_count"] == 0) else 1


if __name__ == "__main__":
    cli_args = parse_args()
    # If running sample evaluation and --output was not explicitly specified,
    # default to sample_output_predictions.csv so root output.csv (518 evaluation rows) is preserved
    out_file = cli_args.output
    if cli_args.eval_samples and "--output" not in sys.argv:
        out_file = Path("sample_output_predictions.csv")

    exit_code = run_pipeline(
        dataset_dir=cli_args.dataset_dir,
        cases_file=cli_args.cases_file,
        output_path=out_file,
        is_eval_samples=cli_args.eval_samples,
        limit=cli_args.limit
    )
    sys.exit(exit_code)
