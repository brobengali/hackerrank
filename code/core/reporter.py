"""Output reporting and serialization module.
Produces compliant output.csv with exact headers and sorted case rows.
"""
import csv
import json
from pathlib import Path
from typing import List
from code.models import CaseAuditResult

class Reporter:
    @staticmethod
    def write_output_csv(results: List[CaseAuditResult], output_path: Path) -> None:
        """Writes audit predictions to output.csv adhering strictly to the contract."""
        # Sort results strictly by case_id
        sorted_results = sorted(results, key=lambda r: r.case_id)

        with open(output_path, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "deletion_status", "steps_json"])

            for r in sorted_results:
                steps_dicts = [s.to_dict() for s in r.steps]
                steps_json_str = json.dumps(steps_dicts, separators=(',', ':'))
                writer.writerow([r.case_id, r.status.value, steps_json_str])
