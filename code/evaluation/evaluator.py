"""Evaluation metrics engine for Ghost Data Still Exists.
Computes case-level status accuracy, step-level precision/recall/F1,
field-level accuracy, and sequence accuracy against ground truth.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import csv
import json

from code.models import DeletionStatus


@dataclass
class EvaluationMetrics:
    total_cases: int
    status_matches: int
    status_accuracy: float
    total_expected_steps: int
    total_actual_steps: int
    step_matches: int
    step_precision: float
    step_recall: float
    step_f1: float
    exact_sequence_matches: int
    sequence_accuracy: float
    field_accuracy: Dict[str, float] = field(default_factory=dict)
    per_case_results: List[Dict[str, Any]] = field(default_factory=list)


class Evaluator:
    @staticmethod
    def evaluate(
        actual_output_path: Path,
        expected_output_path: Path
    ) -> EvaluationMetrics:
        """Compares predicted output.csv against expected ground truth CSV."""
        with open(actual_output_path, "r", encoding="utf-8") as f:
            actual_rows = {r["case_id"]: r for r in csv.DictReader(f)}

        with open(expected_output_path, "r", encoding="utf-8") as f:
            expected_rows = {r["case_id"]: r for r in csv.DictReader(f)}

        total_cases = len(expected_rows)
        status_matches = 0
        total_expected_steps = 0
        total_actual_steps = 0
        step_matches = 0
        exact_sequence_matches = 0

        field_hits = {
            "phase": 0,
            "system_id": 0,
            "resource_id": 0,
            "operation": 0,
            "state": 0,
            "evidence_id": 0
        }
        total_field_comparisons = 0

        per_case_results = []

        for case_id, exp_row in expected_rows.items():
            act_row = actual_rows.get(case_id)
            if not act_row:
                per_case_results.append({
                    "case_id": case_id,
                    "status_match": False,
                    "expected_status": exp_row["deletion_status"],
                    "actual_status": "MISSING",
                    "step_count_expected": len(json.loads(exp_row["steps_json"])),
                    "step_count_actual": 0
                })
                continue

            # Case status comparison
            status_match = (act_row["deletion_status"] == exp_row["deletion_status"])
            if status_match:
                status_matches += 1

            # Parse steps
            try:
                exp_steps = json.loads(exp_row["steps_json"])
            except Exception:
                exp_steps = []

            try:
                act_steps = json.loads(act_row["steps_json"])
            except Exception:
                act_steps = []

            total_expected_steps += len(exp_steps)
            total_actual_steps += len(act_steps)

            # Sequence match
            # Compare steps ignoring step_no
            exp_norm = [
                (s.get("phase"), s.get("system_id"), s.get("resource_id"),
                 s.get("operation"), s.get("state"), s.get("evidence_id"))
                for s in exp_steps
            ]
            act_norm = [
                (s.get("phase"), s.get("system_id"), s.get("resource_id"),
                 s.get("operation"), s.get("state"), s.get("evidence_id"))
                for s in act_steps
            ]

            seq_match = (exp_norm == act_norm)
            if seq_match:
                exact_sequence_matches += 1

            # Step matching & field matching
            case_step_matches = 0
            for i, es in enumerate(exp_steps):
                if i < len(act_steps):
                    as_step = act_steps[i]
                    total_field_comparisons += 1
                    for k in field_hits:
                        if es.get(k) == as_step.get(k):
                            field_hits[k] += 1
                    if (es.get("system_id") == as_step.get("system_id") and
                        es.get("resource_id") == as_step.get("resource_id") and
                        es.get("operation") == as_step.get("operation")):
                        case_step_matches += 1
                        step_matches += 1

            per_case_results.append({
                "case_id": case_id,
                "status_match": status_match,
                "expected_status": exp_row["deletion_status"],
                "actual_status": act_row["deletion_status"],
                "sequence_match": seq_match,
                "step_count_expected": len(exp_steps),
                "step_count_actual": len(act_steps),
                "step_matches": case_step_matches
            })

        status_accuracy = (status_matches / total_cases) if total_cases > 0 else 0.0
        step_precision = (step_matches / total_actual_steps) if total_actual_steps > 0 else 0.0
        step_recall = (step_matches / total_expected_steps) if total_expected_steps > 0 else 0.0
        step_f1 = (2 * step_precision * step_recall / (step_precision + step_recall)) if (step_precision + step_recall) > 0 else 0.0
        sequence_accuracy = (exact_sequence_matches / total_cases) if total_cases > 0 else 0.0

        field_accuracy = {
            k: (v / total_field_comparisons) if total_field_comparisons > 0 else 0.0
            for k, v in field_hits.items()
        }

        return EvaluationMetrics(
            total_cases=total_cases,
            status_matches=status_matches,
            status_accuracy=status_accuracy,
            total_expected_steps=total_expected_steps,
            total_actual_steps=total_actual_steps,
            step_matches=step_matches,
            step_precision=step_precision,
            step_recall=step_recall,
            step_f1=step_f1,
            exact_sequence_matches=exact_sequence_matches,
            sequence_accuracy=sequence_accuracy,
            field_accuracy=field_accuracy,
            per_case_results=per_case_results
        )
