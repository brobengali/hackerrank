"""Comprehensive unit tests for the data loading and schema validation layer.
Covers:
1. Valid data loading using actual repository datasets
2. Missing file error handling
3. Missing fields and malformed headers
4. Duplicate records detection
5. Unexpected values and type validation
6. Output schema contract validation
7. PII masking and structured logging
"""
import unittest
import tempfile
import json
from pathlib import Path

from code.config import Config
from code.core.loader import DataLoader
from code.core.schema_validator import SchemaValidator
from code.core.logging_utils import mask_email, mask_phone, sanitize_text
from code.core.errors import (
    MissingFileError, MissingFieldError, DuplicateRecordError,
    InvalidDataFormatError, MalformedRowError
)
from code.models import DeletionStatus, Phase, Operation, ResourceState

class TestDataLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()

    # =========================================================================
    # 1. Valid Data Loading (Actual Repository Datasets)
    # =========================================================================
    def test_load_actual_deletion_rules(self):
        """Loads and verifies actual deletion_rules.csv."""
        rules = DataLoader.load_deletion_rules(self.config.deletion_rules_path)
        self.assertGreater(len(rules), 0)
        # Exactly 15 deletion rules defined by the platform
        self.assertEqual(len(rules), 15)
        for r in rules:
            self.assertTrue(r.rule_id.startswith("rule_"))
            self.assertIn(r.required_action, {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"})
            self.assertIsNotNone(r.provenance)
            self.assertEqual(r.provenance.source_file, str(self.config.deletion_rules_path))

    def test_load_actual_sample_deletion_cases(self):
        """Loads and verifies actual sample_deletion_requests.csv."""
        cases = DataLoader.load_deletion_cases(self.config.sample_requests_path)
        self.assertEqual(len(cases), 32)
        for c in cases:
            self.assertTrue(c.case_id.startswith("case_"))
            self.assertIn("@", c.email)
            self.assertIn(c.reported_status, {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"})
            self.assertIsNotNone(c.provenance)

    def test_load_actual_user_identities(self):
        """Loads and verifies actual user_identities.csv."""
        identities = DataLoader.load_user_identities(self.config.user_identities_path)
        self.assertGreater(len(identities), 0)
        first = identities[0]
        self.assertIn("user_id", first)
        self.assertIn("email", first)
        self.assertIn("_source_file", first)
        self.assertIn("_row_number", first)

    def test_load_actual_user_audit_log(self):
        """Loads and verifies actual user_audit_log.csv."""
        audit_log = DataLoader.load_user_audit_log(self.config.user_audit_log_path)
        self.assertGreater(len(audit_log), 0)
        first = audit_log[0]
        self.assertIn("audit_id", first)
        self.assertIn("user_id", first)
        self.assertIn("field_name", first)

    def test_load_actual_system_activity(self):
        """Loads and verifies actual system_activity.csv."""
        activity = DataLoader.load_system_activity(self.config.system_activity_path)
        self.assertGreater(len(activity), 0)
        first = activity[0]
        self.assertIn("activity_id", first)
        self.assertIn("event_time", first)

    def test_load_actual_evidence_files(self):
        """Loads and verifies actual evidence_files.csv."""
        manifest = DataLoader.load_evidence_manifest(self.config.evidence_files_path)
        self.assertEqual(len(manifest), 94)
        for m in manifest:
            self.assertTrue(m["file_id"].startswith("evidence_"))
            self.assertTrue(m["file_path"].startswith("evidence/"))

    # =========================================================================
    # 2. Missing Files Tests
    # =========================================================================
    def test_load_missing_file_raises_error(self):
        """Ensures MissingFileError is raised when a target dataset does not exist."""
        nonexistent = self.config.dataset_dir / "nonexistent_dataset_file.csv"
        with self.assertRaises(MissingFileError):
            DataLoader.load_deletion_rules(nonexistent)

    def test_config_validate_missing_path(self):
        """Ensures Config.validate_paths detects missing mandatory files."""
        cfg = Config(repo_root=Path("/invalid/path/that/does/not/exist"))
        with self.assertRaises(MissingFileError):
            cfg.validate_paths()

    # =========================================================================
    # 3. Missing Fields Tests
    # =========================================================================
    def test_missing_header_columns_raises_error(self):
        """Ensures MissingFieldError is raised when a mandatory column is absent."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("rule_id,condition,required_action\n")  # Missing data_category
            f.write("rule_01,profile older than 30d,DELETE\n")
            f_path = Path(f.name)

        try:
            with self.assertRaises(MissingFieldError):
                DataLoader.load_deletion_rules(f_path)
        finally:
            f_path.unlink()

    def test_missing_step_field_in_output_raises_error(self):
        """Ensures output validation detects missing step fields."""
        incomplete_steps = json.dumps([{
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            # missing resource_id
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "evidence_01"
        }])
        with self.assertRaises(MissingFieldError):
            SchemaValidator.validate_output_steps("case_01", "INCOMPLETE", incomplete_steps)

    # =========================================================================
    # 4. Duplicate Records Tests
    # =========================================================================
    def test_duplicate_rule_id_raises_error(self):
        """Ensures DuplicateRecordError is raised for duplicate rule_id entries."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("rule_id,data_category,condition,required_action\n")
            f.write("rule_01,USER_PROFILE,profile requested,DELETE\n")
            f.write("rule_01,USER_PROFILE,duplicate rule,DELETE\n")
            f_path = Path(f.name)

        try:
            with self.assertRaises(DuplicateRecordError):
                DataLoader.load_deletion_rules(f_path)
        finally:
            f_path.unlink()

    def test_duplicate_case_id_raises_error(self):
        """Ensures DuplicateRecordError is raised for duplicate case_id entries."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n")
            f.write("case_01,a@test.com,2026-09-01T10:00:00Z,COMPLETE,2026-09-02T10:00:00Z,2026-09-10T10:00:00Z,Delete me\n")
            f.write("case_01,b@test.com,2026-09-01T10:00:00Z,COMPLETE,2026-09-02T10:00:00Z,2026-09-10T10:00:00Z,Delete me\n")
            f_path = Path(f.name)

        try:
            with self.assertRaises(DuplicateRecordError):
                DataLoader.load_deletion_cases(f_path)
        finally:
            f_path.unlink()

    # =========================================================================
    # 5. Invalid Data and Unexpected Values Tests
    # =========================================================================
    def test_invalid_required_action_raises_error(self):
        """Ensures InvalidDataFormatError is raised for unsupported action strings."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("rule_id,data_category,condition,required_action\n")
            f.write("rule_01,USER_PROFILE,condition,DESTROY_EVERYTHING\n")
            f_path = Path(f.name)

        try:
            with self.assertRaises(InvalidDataFormatError):
                DataLoader.load_deletion_rules(f_path)
        finally:
            f_path.unlink()

    def test_invalid_iso_timestamp_raises_error(self):
        """Ensures invalid timestamps trigger InvalidDataFormatError."""
        with self.assertRaises(InvalidDataFormatError):
            SchemaValidator.validate_iso_timestamp("invalid-date-format", "test_field", "test.csv", 2)

    def test_invalid_reported_status_raises_error(self):
        """Ensures unsupported reported_status triggers InvalidDataFormatError."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n")
            f.write("case_01,a@test.com,2026-09-01T10:00:00Z,PENDING_WORK,2026-09-02T10:00:00Z,2026-09-10T10:00:00Z,Delete me\n")
            f_path = Path(f.name)

        try:
            with self.assertRaises(InvalidDataFormatError):
                DataLoader.load_deletion_cases(f_path)
        finally:
            f_path.unlink()

    def test_not_applicable_with_steps_raises_error(self):
        """Contract violation: NOT_APPLICABLE must have empty steps_json."""
        steps_with_content = json.dumps([{
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_01",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "evidence_01"
        }])
        with self.assertRaises(InvalidDataFormatError):
            SchemaValidator.validate_output_steps("case_01", "NOT_APPLICABLE", steps_with_content)

    def test_non_consecutive_step_numbers_raises_error(self):
        """Step numbers must start at 1 and be consecutive."""
        non_consecutive_steps = json.dumps([
            {
                "step_no": 1,
                "phase": "FINDING",
                "system_id": "account_service",
                "resource_id": "account_01",
                "operation": "REPORT_REMAINING_RECORD",
                "state": "PRESENT",
                "evidence_id": "evidence_01"
            },
            {
                "step_no": 3,  # Expected 2
                "phase": "REMEDIATION",
                "system_id": "account_service",
                "resource_id": "account_01",
                "operation": "DELETE_RECORD",
                "state": "ABSENT",
                "evidence_id": ""
            }
        ])
        with self.assertRaises(InvalidDataFormatError):
            SchemaValidator.validate_output_steps("case_01", "INCOMPLETE", non_consecutive_steps)

    def test_out_of_order_phases_raises_error(self):
        """Phase order must strictly be FINDING -> REMEDIATION -> VERIFICATION."""
        out_of_order_steps = json.dumps([
            {
                "step_no": 1,
                "phase": "VERIFICATION",  # Cannot appear before REMEDIATION in an INCOMPLETE case
                "system_id": "account_service",
                "resource_id": "account_01",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": ""
            },
            {
                "step_no": 2,
                "phase": "REMEDIATION",
                "system_id": "account_service",
                "resource_id": "account_01",
                "operation": "DELETE_RECORD",
                "state": "ABSENT",
                "evidence_id": ""
            }
        ])
        with self.assertRaises(InvalidDataFormatError):
            SchemaValidator.validate_output_steps("case_01", "INCOMPLETE", out_of_order_steps)

    # =========================================================================
    # 6. PII Masking & Logging Tests
    # =========================================================================
    def test_mask_email(self):
        """Verifies email obfuscation."""
        masked = mask_email("nadia.ionescu@yahoo.com")
        self.assertNotIn("nadia.ionescu", masked)
        self.assertEqual(masked, "n***u@y***.com")

    def test_mask_phone(self):
        """Verifies phone number obfuscation."""
        masked = mask_phone("+55 21 90180-9087")
        self.assertNotIn("90180", masked)
        self.assertTrue(masked.endswith("9087"))

    def test_sanitize_text(self):
        """Verifies that arbitrary text messages have emails and phones redacted."""
        raw = "Processing user john.doe@corp.net with phone +1-555-432-8765 completed."
        sanitized = sanitize_text(raw)
        self.assertNotIn("john.doe@corp.net", sanitized)
        self.assertNotIn("432", sanitized)
        self.assertIn("***", sanitized)

if __name__ == "__main__":
    unittest.main()
