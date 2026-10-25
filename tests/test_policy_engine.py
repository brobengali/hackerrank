"""Comprehensive unit tests for the deterministic policy engine.
Covers:
1. Runtime policy parsing from deletion_rules.csv
2. Validation of supported actions and rejection of contradictory rules
3. Rejection of unknown policy categories without inventing defaults
4. Complete deletion, redaction, anonymization, and retention semantics
5. Inspection of prohibited direct PII in retained records
6. Correct handling of permitted account tombstones (stable user_id permitted, direct PII prohibited)
7. Distinguishing compliant retained records from policy violations
8. Verification that policy changes alter evaluations without code changes
9. Evaluation of previously unseen, synthetic records
"""
import unittest
import tempfile
from pathlib import Path

from code.config import Config
from code.models import DeletionRule, Operation, ResourceState
from code.core.policy_engine import PolicyEngine
from code.core.errors import (
    UnknownPolicyCategoryError, ContradictoryPolicyError, InvalidDataFormatError
)

class TestPolicyEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.engine = PolicyEngine.from_file(cls.config.deletion_rules_path)

    # =========================================================================
    # 1. Runtime Parsing & Rule Schema Validation
    # =========================================================================
    def test_runtime_parsing_from_file(self):
        """Verifies that all 15 rules from deletion_rules.csv are parsed dynamically."""
        self.assertEqual(len(self.engine.rules_by_category), 15)
        # Check standard categories are registered
        self.assertEqual(self.engine.get_action_for_category("USER_PROFILE"), "DELETE")
        self.assertEqual(self.engine.get_action_for_category("ACCOUNT_TOMBSTONE"), "REDACT")
        self.assertEqual(self.engine.get_action_for_category("ANALYTICS_PROFILE"), "ANONYMIZE")
        self.assertEqual(self.engine.get_action_for_category("SECURITY_AUDIT_LOG"), "RETAIN")
        self.assertEqual(self.engine.get_action_for_category("BACKUP_ARCHIVE"), "RETAIN")

    def test_reject_unknown_policy_category(self):
        """Strict Rule: Unknown categories must be rejected rather than guessing defaults."""
        with self.assertRaises(UnknownPolicyCategoryError):
            self.engine.get_rule("INVENTED_NONEXISTENT_CATEGORY")

        with self.assertRaises(UnknownPolicyCategoryError):
            self.engine.evaluate_record(
                category="INVENTED_NONEXISTENT_CATEGORY",
                observed_state=ResourceState.PRESENT
            )

    def test_reject_contradictory_policy(self):
        """Contradictory rules for the same category must raise ContradictoryPolicyError."""
        contradictory_rules = [
            DeletionRule(rule_id="r1", data_category="USER_PROFILE", condition="Always", required_action="DELETE"),
            DeletionRule(rule_id="r2", data_category="USER_PROFILE", condition="Always", required_action="RETAIN"),
        ]
        with self.assertRaises(ContradictoryPolicyError):
            PolicyEngine(contradictory_rules)

    # =========================================================================
    # 2. Deletion Semantics (DELETE)
    # =========================================================================
    def test_delete_rule_violation_when_present(self):
        """Records requiring DELETE are non-compliant when PRESENT."""
        eval_result = self.engine.evaluate_record(
            category="USER_PROFILE",
            observed_state=ResourceState.PRESENT,
            record_fields={"account_id": "acc_001", "email": "test@example.com"}
        )
        self.assertFalse(eval_result.is_compliant)
        self.assertEqual(eval_result.required_action, "DELETE")
        self.assertEqual(eval_result.finding_operation, Operation.REPORT_REMAINING_RECORD)
        self.assertEqual(eval_result.remediation_operation, Operation.DELETE_RECORD)
        self.assertEqual(eval_result.verification_operation, Operation.VERIFY_RECORD_ABSENT)
        self.assertEqual(eval_result.target_remediation_state, ResourceState.ABSENT)

    def test_delete_rule_compliant_when_absent(self):
        """Records requiring DELETE are compliant when ABSENT."""
        eval_result = self.engine.evaluate_record(
            category="USER_PROFILE",
            observed_state=ResourceState.ABSENT
        )
        self.assertTrue(eval_result.is_compliant)
        self.assertEqual(eval_result.required_action, "DELETE")
        self.assertIsNone(eval_result.finding_operation)
        self.assertEqual(eval_result.verification_operation, Operation.VERIFY_RECORD_ABSENT)

    # =========================================================================
    # 3. Account Tombstone Semantics (Rule 15: REDACT)
    # =========================================================================
    def test_tombstone_compliant_with_stable_user_id_only(self):
        """Compliant tombstone: Stable user_id preserved, direct PII removed."""
        tombstone_fields = {
            "resource_id": "tombstone_101",
            "subject_reference": "user_49",
            "name": None,
            "email": None,
            "phone": None,
            "email_hash": None,
            "account_status": "DELETED"
        }
        eval_result = self.engine.evaluate_record(
            category="ACCOUNT_TOMBSTONE",
            observed_state=ResourceState.PRESENT,
            record_fields=tombstone_fields
        )
        self.assertTrue(eval_result.is_compliant, "Tombstone with only stable user_id must be compliant")
        self.assertEqual(eval_result.required_action, "REDACT")
        self.assertEqual(eval_result.verification_operation, Operation.VERIFY_RECORD_REDACTED)

    def test_tombstone_violation_when_direct_pii_exposed(self):
        """Non-compliant tombstone: Exposes direct identifiers (name, email, phone)."""
        tombstone_fields = {
            "resource_id": "tombstone_102",
            "subject_reference": "user_50",
            "name": "Ren Mori",
            "email": "mori.ren@gmail.com",
            "phone": "+81 90 1234 5678",
            "email_hash": "abc123hash",
            "account_status": "DELETED"
        }
        eval_result = self.engine.evaluate_record(
            category="ACCOUNT_TOMBSTONE",
            observed_state=ResourceState.PRESENT,
            record_fields=tombstone_fields
        )
        self.assertFalse(eval_result.is_compliant)
        self.assertEqual(eval_result.required_action, "REDACT")
        self.assertEqual(eval_result.finding_operation, Operation.REPORT_EXPOSED_PII)
        self.assertEqual(eval_result.remediation_operation, Operation.REDACT_RECORD)
        self.assertEqual(eval_result.verification_operation, Operation.VERIFY_RECORD_REDACTED)
        self.assertIn("name", eval_result.exposed_prohibited_fields)
        self.assertIn("email", eval_result.exposed_prohibited_fields)
        self.assertIn("phone", eval_result.exposed_prohibited_fields)

    # =========================================================================
    # 4. Redaction Semantics (SUPPORT_MESSAGE, EMAIL_DELIVERY_LOG)
    # =========================================================================
    def test_support_message_redaction(self):
        """Support message with customer contact info is a REDACT violation."""
        exposed_msg = {
            "message_id": "msg_001",
            "requester_email": "customer@example.com",
            "requester_name": "Alice Smith",
            "message_body": "Please deliver to apartment 4B."
        }
        eval_result = self.engine.evaluate_record(
            category="SUPPORT_MESSAGE",
            observed_state=ResourceState.PRESENT,
            record_fields=exposed_msg
        )
        self.assertFalse(eval_result.is_compliant)
        self.assertEqual(eval_result.finding_operation, Operation.REPORT_EXPOSED_PII)
        self.assertEqual(eval_result.remediation_operation, Operation.REDACT_RECORD)

        # Once redacted, it is compliant
        clean_msg = {
            "message_id": "msg_001",
            "requester_email": None,
            "requester_name": None,
            "message_body": "Please deliver to apartment 4B."
        }
        eval_clean = self.engine.evaluate_record(
            category="SUPPORT_MESSAGE",
            observed_state=ResourceState.REDACTED,
            record_fields=clean_msg
        )
        self.assertTrue(eval_clean.is_compliant)
        self.assertEqual(eval_clean.verification_operation, Operation.VERIFY_RECORD_REDACTED)

    # =========================================================================
    # 5. Anonymization Semantics (ANALYTICS_PROFILE, PRODUCT_TELEMETRY)
    # =========================================================================
    def test_analytics_profile_anonymization(self):
        """Analytics profile attributable to user violates policy."""
        attributable_profile = {
            "profile_id": "ap_001",
            "user_id": "user_42",
            "email": "user@test.com",
            "events_count": 45
        }
        eval_result = self.engine.evaluate_record(
            category="ANALYTICS_PROFILE",
            observed_state=ResourceState.PRESENT,
            record_fields=attributable_profile
        )
        self.assertFalse(eval_result.is_compliant)
        self.assertEqual(eval_result.finding_operation, Operation.REPORT_EXPOSED_PII)
        self.assertEqual(eval_result.remediation_operation, Operation.ANONYMIZE_RECORD)
        self.assertEqual(eval_result.verification_operation, Operation.VERIFY_RECORD_ANONYMIZED)

        # Anonymized profile (unlinked cohort)
        anonymized_profile = {
            "profile_id": "ap_001",
            "user_id": None,
            "email": None,
            "cohort": "mobile_browser"
        }
        eval_clean = self.engine.evaluate_record(
            category="ANALYTICS_PROFILE",
            observed_state=ResourceState.ANONYMIZED,
            record_fields=anonymized_profile
        )
        self.assertTrue(eval_clean.is_compliant)
        self.assertEqual(eval_clean.verification_operation, Operation.VERIFY_RECORD_ANONYMIZED)

    # =========================================================================
    # 6. Retention Semantics (SECURITY_AUDIT_LOG, BACKUP_ARCHIVE)
    # =========================================================================
    def test_security_audit_log_retention(self):
        """Security audit logs must remain PRESENT."""
        eval_result = self.engine.evaluate_record(
            category="SECURITY_AUDIT_LOG",
            observed_state=ResourceState.PRESENT,
            record_fields={"subject_reference": "user_43", "event_code": "LOGIN"}
        )
        self.assertTrue(eval_result.is_compliant)
        self.assertEqual(eval_result.verification_operation, Operation.VERIFY_RECORD_PRESENT)

    def test_backup_archive_restore_risk(self):
        """Backup archive with active restore access violates retention restrictions."""
        eval_risk = self.engine.evaluate_record(
            category="BACKUP_ARCHIVE",
            observed_state=ResourceState.ACTIVE,
            details={"restore_allowed": True}
        )
        self.assertFalse(eval_risk.is_compliant)
        self.assertEqual(eval_risk.finding_operation, Operation.REPORT_RESTORE_RISK)
        self.assertEqual(eval_risk.remediation_operation, Operation.BLOCK_RESTORE)
        self.assertEqual(eval_risk.verification_operation, Operation.VERIFY_RESTORE_BLOCKED)

        # Backup archive with blocked restore access is compliant
        eval_blocked = self.engine.evaluate_record(
            category="BACKUP_ARCHIVE",
            observed_state=ResourceState.BLOCKED,
            details={"restore_allowed": False}
        )
        self.assertTrue(eval_blocked.is_compliant)
        self.assertEqual(eval_blocked.verification_operation, Operation.VERIFY_RESTORE_BLOCKED)

    # =========================================================================
    # 7. Policy Changes Without Code Modifications
    # =========================================================================
    def test_policy_change_alters_evaluation_dynamically(self):
        """Modifying rules in policy alters evaluation without code changes."""
        # Baseline: SUPPORT_MESSAGE is REDACT
        baseline_eval = self.engine.evaluate_record(
            category="SUPPORT_MESSAGE",
            observed_state=ResourceState.PRESENT,
            record_fields={"requester_email": "test@corp.com"}
        )
        self.assertEqual(baseline_eval.remediation_operation, Operation.REDACT_RECORD)

        # Dynamic Policy Update: Change SUPPORT_MESSAGE to DELETE
        updated_rules = [
            r if r.data_category != "SUPPORT_MESSAGE" 
            else DeletionRule(rule_id="rule_05", data_category="SUPPORT_MESSAGE", condition="Always", required_action="DELETE")
            for r in self.engine.rules_by_category.values()
        ]
        updated_engine = PolicyEngine(updated_rules)

        updated_eval = updated_engine.evaluate_record(
            category="SUPPORT_MESSAGE",
            observed_state=ResourceState.PRESENT,
            record_fields={"requester_email": "test@corp.com"}
        )
        self.assertEqual(updated_eval.required_action, "DELETE")
        self.assertEqual(updated_eval.finding_operation, Operation.REPORT_REMAINING_RECORD)
        self.assertEqual(updated_eval.remediation_operation, Operation.DELETE_RECORD)
        self.assertEqual(updated_eval.verification_operation, Operation.VERIFY_RECORD_ABSENT)

    # =========================================================================
    # 8. Evaluation of Previously Unseen Record Types
    # =========================================================================
    def test_unseen_record_type_evaluation(self):
        """Proves that a new, previously unseen record type is correctly evaluated."""
        custom_rules = list(self.engine.rules_by_category.values()) + [
            DeletionRule(
                rule_id="rule_99",
                data_category="UNSEEN_FINANCIAL_INVOICE",
                condition="Invoice context retained for taxation",
                required_action="RETAIN"
            ),
            DeletionRule(
                rule_id="rule_100",
                data_category="UNSEEN_SESSION_COOKIE",
                condition="Always",
                required_action="DELETE"
            )
        ]
        custom_engine = PolicyEngine(custom_rules)

        # Evaluate unseen financial invoice
        eval_invoice = custom_engine.evaluate_record(
            category="UNSEEN_FINANCIAL_INVOICE",
            observed_state=ResourceState.PRESENT
        )
        self.assertTrue(eval_invoice.is_compliant)
        self.assertEqual(eval_invoice.verification_operation, Operation.VERIFY_RECORD_PRESENT)

        # Evaluate unseen session cookie
        eval_cookie = custom_engine.evaluate_record(
            category="UNSEEN_SESSION_COOKIE",
            observed_state=ResourceState.PRESENT
        )
        self.assertFalse(eval_cookie.is_compliant)
        self.assertEqual(eval_cookie.finding_operation, Operation.REPORT_REMAINING_RECORD)
        self.assertEqual(eval_cookie.remediation_operation, Operation.DELETE_RECORD)
        self.assertEqual(eval_cookie.verification_operation, Operation.VERIFY_RECORD_ABSENT)

if __name__ == "__main__":
    unittest.main()
