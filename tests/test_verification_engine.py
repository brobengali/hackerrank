"""Unit test suite for the deterministic verification engine and post-model safety gate.
Covers:
1. All three statuses (COMPLETE, INCOMPLETE, NOT_APPLICABLE).
2. Missing evidence rejection (missing evidence must never count as verification).
3. Residual personal data detection blocking completion.
4. Active resurrection paths blocking completion.
5. Compliant tombstones (stable user_id permitted; direct PII prohibited).
6. Retention violations (missing required retained records).
7. Inaccessible system handling.
8. Demonstration that the safety gate overrides incorrect model assessments.
"""
import unittest

from code.core.verification_engine import VerificationEngine, PostModelSafetyGate
from code.models import (
    DeletionCase, DeletionStatus, Operation, ResourceState, Phase, Step,
    InvestigationFinding, ProcessStatus, ResurrectionRisk, ResurrectionReport
)

class TestVerificationEngineAndSafetyGate(unittest.TestCase):
    def setUp(self):
        self.engine = VerificationEngine()
        self.gate = PostModelSafetyGate(self.engine)
        self.dummy_case = DeletionCase(
            case_id="case_verify_001",
            email="subject@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Please delete all my personal data."
        )

    # =========================================================================
    # 1. NOT_APPLICABLE Status
    # =========================================================================
    def test_status_not_applicable_when_deletion_not_requested(self):
        """Non-deletion requests must evaluate to NOT_APPLICABLE and override model COMPLETE."""
        case_access = DeletionCase(
            case_id="case_access_002",
            email="access@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="I want to export and download a copy of my data."
        )

        # Model naively assessed COMPLETE based on reported_status
        eval_result = self.gate.enforce_safety_gate(
            case=case_access,
            is_deletion_authorized=False,
            findings=[],
            verification_steps=[],
            model_proposed_status=DeletionStatus.COMPLETE
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.NOT_APPLICABLE)
        self.assertTrue(eval_result.was_overridden)
        self.assertIn("INVARIANT_REQUEST_AUTHORIZED", eval_result.failed_invariants)
        self.assertIsNotNone(eval_result.override_reason)

    # =========================================================================
    # 2. COMPLETE Status
    # =========================================================================
    def test_status_complete_when_all_invariants_pass(self):
        """Evaluates to COMPLETE when all deletion, redaction, retention, and resurrection invariants pass."""
        verif_steps = [
            Step(step_no=1, phase=Phase.VERIFICATION, system_id="account_service", resource_id="account_101", operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id="ev_sql_01"),
            Step(step_no=2, phase=Phase.VERIFICATION, system_id="security_service", resource_id="audit_101", operation=Operation.VERIFY_RECORD_PRESENT, state=ResourceState.PRESENT, evidence_id="ev_sec_01")
        ]

        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[],
            verification_steps=verif_steps,
            model_proposed_status=DeletionStatus.COMPLETE,
            retained_records_verified=True
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.COMPLETE)
        self.assertFalse(eval_result.was_overridden)
        self.assertEqual(len(eval_result.failed_invariants), 0)

    # =========================================================================
    # 3. Residual Personal Data Blocks Completion
    # =========================================================================
    def test_status_incomplete_with_residual_personal_data_overrides_model(self):
        """Residual undeleted records block COMPLETE and cause safety gate to override model."""
        residual_finding = InvestigationFinding(
            system_id="account_service",
            resource_id="account_ghost",
            operation=Operation.REPORT_REMAINING_RECORD,
            state=ResourceState.PRESENT,
            evidence_id="ev_db_snapshot",
            category="USER_PROFILE",
            observed_at="2026-09-02T10:00:00Z",
            source_file="ev_db_snapshot"
        )

        # Model claims COMPLETE because workflow reported COMPLETE
        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[residual_finding],
            verification_steps=[],
            model_proposed_status=DeletionStatus.COMPLETE
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(eval_result.was_overridden)
        self.assertIn("INVARIANT_NO_RESIDUAL_RECORDS", eval_result.failed_invariants)
        self.assertIn("Residual records", eval_result.override_reason)

    # =========================================================================
    # 4. Active Resurrection Paths Block Completion
    # =========================================================================
    def test_status_incomplete_with_active_resurrection_path(self):
        """Active data flow or restore risk blocks COMPLETE and overrides model assessment."""
        flow_finding = InvestigationFinding(
            system_id="integration_service",
            resource_id="data_flow_active",
            operation=Operation.REPORT_ACTIVE_DATA_FLOW,
            state=ResourceState.ACTIVE,
            evidence_id="ev_connector_config",
            category="DATA_FLOW",
            observed_at="2026-09-02T10:00:00Z",
            source_file="ev_connector_config"
        )

        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[flow_finding],
            verification_steps=[],
            model_proposed_status=DeletionStatus.COMPLETE
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(eval_result.was_overridden)
        self.assertIn("INVARIANT_RESURRECTION_CONTROLLED", eval_result.failed_invariants)

    # =========================================================================
    # 5. Missing Evidence Never Counts as Verification
    # =========================================================================
    def test_missing_evidence_blocks_complete_verification(self):
        """Candidate complete case with empty evidence_id must fail completion invariants."""
        unverified_steps = [
            Step(step_no=1, phase=Phase.VERIFICATION, system_id="account_service", resource_id="account_unverified", operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id="")
        ]

        # Model claims COMPLETE without evidence
        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[],
            verification_steps=unverified_steps,
            model_proposed_status=DeletionStatus.COMPLETE
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(eval_result.was_overridden)
        self.assertIn("INVARIANT_EVIDENCE_PROVENANCE_REQUIRED", eval_result.failed_invariants)

    # =========================================================================
    # 6. Retention Violations
    # =========================================================================
    def test_missing_retained_record_blocks_completion(self):
        """Missing or deleted policy-required retained records block completion."""
        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[],
            verification_steps=[],
            model_proposed_status=DeletionStatus.COMPLETE,
            retained_records_verified=False
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(eval_result.was_overridden)
        self.assertIn("INVARIANT_RETAINED_RECORDS_AVAILABLE", eval_result.failed_invariants)

    # =========================================================================
    # 7. Permitted Tombstones Compliant
    # =========================================================================
    def test_compliant_tombstone_allows_completion(self):
        """Permitted tombstone retaining only internal reference does NOT fail tombstone invariant."""
        verif_steps = [
            Step(step_no=1, phase=Phase.VERIFICATION, system_id="identity_service", resource_id="tombstone_clean", operation=Operation.VERIFY_RECORD_REDACTED, state=ResourceState.REDACTED, evidence_id="ev_tomb_01"),
            Step(step_no=2, phase=Phase.VERIFICATION, system_id="security_service", resource_id="audit_clean", operation=Operation.VERIFY_RECORD_PRESENT, state=ResourceState.PRESENT, evidence_id="ev_sec_01")
        ]

        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[],
            verification_steps=verif_steps,
            model_proposed_status=DeletionStatus.COMPLETE
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.COMPLETE)
        self.assertNotIn("INVARIANT_PERMITTED_TOMBSTONES_COMPLIANT", eval_result.failed_invariants)

    # =========================================================================
    # 8. Inaccessible Systems
    # =========================================================================
    def test_inaccessible_system_blocks_completion(self):
        """Inaccessible relevant system fails completion and overrides model assessment."""
        eval_result = self.gate.enforce_safety_gate(
            case=self.dummy_case,
            is_deletion_authorized=True,
            findings=[],
            verification_steps=[],
            model_proposed_status=DeletionStatus.COMPLETE,
            has_inaccessible_systems=True
        )

        self.assertEqual(eval_result.final_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(eval_result.was_overridden)
        self.assertIn("INVARIANT_ALL_SYSTEMS_ACCESSIBLE", eval_result.failed_invariants)

if __name__ == "__main__":
    unittest.main()
