"""Schema validation module for the deletion audit agent.
Enforces strict schema compliance, data typing, ISO-8601 validation,
duplicate detection, and output format verification.
"""
import re
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from code.models import (
    DeletionStatus, Phase, Operation, ResourceState,
    ValidationIssue, ValidationSeverity
)
from code.core.errors import (
    MissingFieldError, MalformedRowError, DuplicateRecordError,
    InvalidDataFormatError
)

# Standard required columns for all participant datasets
SCHEMAS: Dict[str, List[str]] = {
    "deletion_rules": ["rule_id", "data_category", "condition", "required_action"],
    "deletion_requests": ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"],
    "user_identities": ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
    "user_audit_log": ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
    "system_activity": ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"],
    "evidence_files": ["file_id", "file_path", "origin", "captured_at"],
    "output": ["case_id", "deletion_status", "steps_json"],
}

ALLOWED_ACTIONS: Set[str] = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}
ALLOWED_REPORTED_STATUS: Set[str] = {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"}

STEP_REQUIRED_FIELDS: Set[str] = {
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
}

ALLOWED_PHASES: Set[str] = {p.value for p in Phase}
ALLOWED_OPERATIONS: Set[str] = {o.value for o in Operation}
ALLOWED_STATES: Set[str] = {s.value for s in ResourceState}


class SchemaValidator:
    """Performs validation checks on input datasets and final output submissions."""

    @staticmethod
    def validate_iso_timestamp(ts: str, field_name: str, source_file: str, row_no: int) -> datetime:
        """Validates that a string is a valid ISO-8601 timestamp."""
        if not ts or not isinstance(ts, str):
            raise InvalidDataFormatError(
                f"Field '{field_name}' must be a non-empty ISO-8601 timestamp string",
                {"source_file": source_file, "row": row_no, "value": ts}
            )
        try:
            # Handle 'Z' suffix for python < 3.11 compatibility
            clean_ts = ts.replace("Z", "+00:00")
            return datetime.fromisoformat(clean_ts)
        except Exception as e:
            raise InvalidDataFormatError(
                f"Invalid ISO-8601 timestamp '{ts}' in field '{field_name}': {e}",
                {"source_file": source_file, "row": row_no, "value": ts}
            )

    @classmethod
    def validate_header(cls, file_type: str, actual_header: List[str], source_file: str) -> None:
        """Validates that the required columns are present in the dataset header."""
        if file_type not in SCHEMAS:
            raise ValueError(f"Unknown file type: {file_type}")
        
        expected = SCHEMAS[file_type]
        actual_set = set(actual_header)
        missing = [col for col in expected if col not in actual_set]
        if missing:
            raise MissingFieldError(
                f"Dataset '{source_file}' is missing required columns: {missing}",
                {"expected": expected, "actual": actual_header, "missing": missing}
            )

    @classmethod
    def validate_deletion_rule_row(cls, row: Dict[str, str], row_no: int, source_file: str, seen_ids: Set[str]) -> None:
        """Validates a single row from deletion_rules.csv."""
        rule_id = row.get("rule_id", "").strip()
        if not rule_id:
            raise MalformedRowError(f"Missing rule_id at row {row_no}", {"source_file": source_file, "row": row_no})
        if rule_id in seen_ids:
            raise DuplicateRecordError(f"Duplicate rule_id '{rule_id}' at row {row_no}", {"source_file": source_file, "rule_id": rule_id})
        seen_ids.add(rule_id)

        action = row.get("required_action", "").strip().upper()
        if action not in ALLOWED_ACTIONS:
            raise InvalidDataFormatError(
                f"Invalid required_action '{action}' for rule '{rule_id}'. Allowed: {ALLOWED_ACTIONS}",
                {"source_file": source_file, "row": row_no, "rule_id": rule_id, "action": action}
            )

    @classmethod
    def validate_deletion_request_row(cls, row: Dict[str, str], row_no: int, source_file: str, seen_ids: Set[str]) -> None:
        """Validates a single row from deletion_requests.csv."""
        case_id = row.get("case_id", "").strip()
        if not case_id:
            raise MalformedRowError(f"Missing case_id at row {row_no}", {"source_file": source_file, "row": row_no})
        if case_id in seen_ids:
            raise DuplicateRecordError(f"Duplicate case_id '{case_id}' at row {row_no}", {"source_file": source_file, "case_id": case_id})
        seen_ids.add(case_id)

        email = row.get("email", "").strip()
        if not email or "@" not in email:
            raise InvalidDataFormatError(f"Malformed or missing email for case '{case_id}'", {"source_file": source_file, "row": row_no, "case_id": case_id})

        status = row.get("reported_status", "").strip()
        if status not in ALLOWED_REPORTED_STATUS:
            raise InvalidDataFormatError(
                f"Invalid reported_status '{status}' for case '{case_id}'. Allowed: {ALLOWED_REPORTED_STATUS}",
                {"source_file": source_file, "row": row_no, "case_id": case_id, "status": status}
            )

        # Validate timestamps
        cls.validate_iso_timestamp(row.get("requested_at", ""), "requested_at", source_file, row_no)
        cls.validate_iso_timestamp(row.get("reported_at", ""), "reported_at", source_file, row_no)
        cls.validate_iso_timestamp(row.get("audit_at", ""), "audit_at", source_file, row_no)

    @classmethod
    def validate_user_identity_row(cls, row: Dict[str, str], row_no: int, source_file: str, seen_ids: Set[str]) -> None:
        """Validates a single row from user_identities.csv."""
        user_id = row.get("user_id", "").strip()
        if not user_id:
            raise MalformedRowError(f"Missing user_id at row {row_no}", {"source_file": source_file, "row": row_no})
        if user_id in seen_ids:
            raise DuplicateRecordError(f"Duplicate user_id '{user_id}' at row {row_no}", {"source_file": source_file, "user_id": user_id})
        seen_ids.add(user_id)

        email = row.get("email", "").strip()
        if not email or "@" not in email:
            raise InvalidDataFormatError(f"Malformed or missing email for user '{user_id}'", {"source_file": source_file, "row": row_no, "user_id": user_id})

        cls.validate_iso_timestamp(row.get("updated_at", ""), "updated_at", source_file, row_no)

    @classmethod
    def validate_user_audit_log_row(cls, row: Dict[str, str], row_no: int, source_file: str, seen_ids: Set[str]) -> None:
        """Validates a single row from user_audit_log.csv."""
        audit_id = row.get("audit_id", "").strip()
        if not audit_id:
            raise MalformedRowError(f"Missing audit_id at row {row_no}", {"source_file": source_file, "row": row_no})
        if audit_id in seen_ids:
            raise DuplicateRecordError(f"Duplicate audit_id '{audit_id}' at row {row_no}", {"source_file": source_file, "audit_id": audit_id})
        seen_ids.add(audit_id)

        user_id = row.get("user_id", "").strip()
        if not user_id:
            raise MalformedRowError(f"Missing user_id for audit_id '{audit_id}' at row {row_no}", {"source_file": source_file, "row": row_no})

        cls.validate_iso_timestamp(row.get("event_time", ""), "event_time", source_file, row_no)

    @classmethod
    def validate_system_activity_row(cls, row: Dict[str, str], row_no: int, source_file: str, seen_ids: Set[str]) -> None:
        """Validates a single row from system_activity.csv."""
        act_id = row.get("activity_id", "").strip()
        if not act_id:
            raise MalformedRowError(f"Missing activity_id at row {row_no}", {"source_file": source_file, "row": row_no})
        if act_id in seen_ids:
            raise DuplicateRecordError(f"Duplicate activity_id '{act_id}' at row {row_no}", {"source_file": source_file, "activity_id": act_id})
        seen_ids.add(act_id)

        cls.validate_iso_timestamp(row.get("event_time", ""), "event_time", source_file, row_no)

    @classmethod
    def validate_evidence_file_row(cls, row: Dict[str, str], row_no: int, source_file: str, seen_ids: Set[str]) -> None:
        """Validates a single row from evidence_files.csv."""
        file_id = row.get("file_id", "").strip()
        if not file_id:
            raise MalformedRowError(f"Missing file_id at row {row_no}", {"source_file": source_file, "row": row_no})
        if file_id in seen_ids:
            raise DuplicateRecordError(f"Duplicate file_id '{file_id}' at row {row_no}", {"source_file": source_file, "file_id": file_id})
        seen_ids.add(file_id)

        cls.validate_iso_timestamp(row.get("captured_at", ""), "captured_at", source_file, row_no)

    @classmethod
    def validate_output_steps(cls, case_id: str, status_str: str, steps_json_str: str) -> List[Dict[str, Any]]:
        """Validates the output row contract for submission, including steps ordering and fields."""
        if status_str not in {s.value for s in DeletionStatus}:
            raise InvalidDataFormatError(f"Invalid deletion_status '{status_str}' for case '{case_id}'")

        try:
            steps = json.loads(steps_json_str)
        except Exception as e:
            raise InvalidDataFormatError(f"Malformed JSON in steps_json for case '{case_id}': {e}")

        if not isinstance(steps, list):
            raise InvalidDataFormatError(f"steps_json must be a JSON array for case '{case_id}'")

        # NOT_APPLICABLE contract: steps_json must be empty
        if status_str == DeletionStatus.NOT_APPLICABLE.value:
            if len(steps) != 0:
                raise InvalidDataFormatError(
                    f"Case '{case_id}' is NOT_APPLICABLE but steps_json has {len(steps)} steps (expected [])"
                )
            return []

        # COMPLETE and INCOMPLETE cases must have at least one step
        if len(steps) == 0:
            raise InvalidDataFormatError(
                f"Case '{case_id}' has status '{status_str}' but steps_json is empty. Only NOT_APPLICABLE cases may have empty steps."
            )

        # Validate individual steps
        phase_sequence = []
        for i, s in enumerate(steps, start=1):
            if not isinstance(s, dict):
                raise InvalidDataFormatError(f"Step {i} in case '{case_id}' is not a JSON object")

            # Validate required step keys
            missing_keys = STEP_REQUIRED_FIELDS - set(s.keys())
            if missing_keys:
                raise MissingFieldError(f"Step {i} in case '{case_id}' is missing keys: {missing_keys}")

            if s["step_no"] != i:
                raise InvalidDataFormatError(f"Step {i} in case '{case_id}' has non-consecutive step_no {s['step_no']}")

            phase = s["phase"]
            if phase not in ALLOWED_PHASES:
                raise InvalidDataFormatError(f"Step {i} in case '{case_id}' has invalid phase '{phase}'")
            phase_sequence.append(phase)

            op = s["operation"]
            if op not in ALLOWED_OPERATIONS:
                raise InvalidDataFormatError(f"Step {i} in case '{case_id}' has invalid operation '{op}'")

            state = s["state"]
            if state not in ALLOWED_STATES:
                raise InvalidDataFormatError(f"Step {i} in case '{case_id}' has invalid state '{state}'")

            ev_id = s.get("evidence_id", "")
            # COMPLETE cases must only have VERIFICATION steps with evidence citations
            if status_str == DeletionStatus.COMPLETE.value:
                if phase != Phase.VERIFICATION.value:
                    raise InvalidDataFormatError(f"COMPLETE case '{case_id}' step {i} has non-verification phase '{phase}'")
                if not ev_id:
                    raise InvalidDataFormatError(f"COMPLETE case '{case_id}' step {i} is missing evidence_id citation")

            # INCOMPLETE cases: findings must cite evidence, remediations and future checks have empty evidence_id
            if status_str == DeletionStatus.INCOMPLETE.value:
                if phase == Phase.FINDING.value and not ev_id:
                    raise InvalidDataFormatError(f"INCOMPLETE case '{case_id}' finding step {i} is missing evidence_id")
                elif phase in [Phase.REMEDIATION.value, Phase.VERIFICATION.value] and ev_id != "":
                    raise InvalidDataFormatError(f"INCOMPLETE case '{case_id}' step {i} ({phase}) must have empty evidence_id, got '{ev_id}'")

        # Verify phase sequence ordering: FINDING -> REMEDIATION -> VERIFICATION
        phase_ranks = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        current_rank = 1
        for p in phase_sequence:
            rank = phase_ranks[p]
            if rank < current_rank:
                raise InvalidDataFormatError(
                    f"Out-of-order phase in case '{case_id}': saw {p} after phase with rank {current_rank}"
                )
            current_rank = rank

        return steps

    @classmethod
    def validate_output_csv(cls, output_path: Path, expected_count: Optional[int] = None) -> Tuple[bool, List[str]]:
        """Validates the completed output CSV against file, header, sorting, and step schemas."""
        errors: List[str] = []
        if not output_path.exists():
            return False, [f"Output file does not exist: {output_path}"]

        with open(output_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header != ["case_id", "deletion_status", "steps_json"]:
                errors.append(f"Invalid output header: {header}. Expected ['case_id', 'deletion_status', 'steps_json']")

            last_case_id = ""
            row_count = 0
            for row_no, row in enumerate(reader, start=2):
                row_count += 1
                if len(row) != 3:
                    errors.append(f"Row {row_no}: expected 3 columns, got {len(row)}")
                    continue

                case_id, status_str, steps_json = row
                # Check sort order
                if case_id < last_case_id:
                    errors.append(f"Row {row_no}: case_id '{case_id}' out of ascending order (saw after '{last_case_id}')")
                last_case_id = case_id

                # Validate steps contract
                try:
                    cls.validate_output_steps(case_id, status_str, steps_json)
                except Exception as e:
                    errors.append(f"Row {row_no} ({case_id}): {e}")

        if expected_count is not None and row_count != expected_count:
            errors.append(f"Expected {expected_count} rows, got {row_count}")

        return (len(errors) == 0, errors)
