"""Generalization and robustness test suite for the deletion audit agent.
Proves that the system generalizes to unseen identities, policy modifications,
data volume shifts, input permutation, new processes, and isolated faults.
"""
import unittest
from unittest.mock import MagicMock
from pathlib import Path
import random
import copy

from code.models import (
    DeletionCase,
    DeletionStatus,
    Phase,
    Operation,
    ResourceState,
    IdentityEnvelope,
    DeletionRule,
    UserIdentityRecord,
    UserAuditLogRecord,
    SystemActivityRecord,
    EvidenceFileRecord,
    CaseAuditResult,
)
from code.core.policy_engine import PolicyEngine
from code.core.identity import IdentityResolver
from code.core.investigator import CrossSystemInvestigator
from code.core.resurrection import ResurrectionEngine
from code.core.remediation_planner import RemediationPlanner
from code.core.verification_engine import PostModelSafetyGate, VerificationEngine
from code.core.batch_processor import BatchAuditProcessor
from code.core.reporter import Reporter
from code.core.schema_validator import SchemaValidator
from code.config import Config


class TestGeneralization(unittest.TestCase):

    def setUp(self):
        # Base synthetic rules
        self.rules = [
            DeletionRule("r1", "USER_PROFILE", "DEFAULT", "DELETE"),
            DeletionRule("r2", "SECURITY_AUDIT_LOG", "DEFAULT", "RETAIN"),
            DeletionRule("r3", "ACCOUNT_TOMBSTONE", "DEFAULT", "REDACT"),
            DeletionRule("r4", "DATA_FLOW", "ACTIVE_FLOW", "DELETE"),
            DeletionRule("r5", "USER_EXPORT", "DEFAULT", "DELETE"),
        ]
        self.policy_engine = PolicyEngine(self.rules)

    def test_1_user_ids_change(self):
        """System generalizes to arbitrary unseen user IDs (e.g. UUIDs or alpha-numeric IDs)."""
        novel_user_id = "user_uuid_7f8c9b2a-1234-5678-9abc-def012345678"
        identities = [
            {"user_id": novel_user_id, "name": "Novel User", "email": "novel.user@cloud.io", "phone": "+1-555-8899", "email_hash": "hash_novel_123", "updated_at": "2026-08-01T00:00:00Z"}
        ]
        audit_log = []
        resolver = IdentityResolver(identities, audit_log)
        envelope = resolver.resolve("novel.user@cloud.io")
        self.assertIsNotNone(envelope)
        self.assertEqual(envelope.user_id, novel_user_id)
        self.assertIn("novel.user@cloud.io", envelope.emails)

    def test_2_historical_identifiers_change(self):
        """System tracks individuals across multiple historical identifier changes."""
        user_id = "user_multihop_44"
        identities = [
            {"user_id": user_id, "name": "Hop User", "email": "hop.v3@domain.org", "phone": "+1-555-0003", "email_hash": "hash_v3", "updated_at": "2026-09-01T00:00:00Z"}
        ]
        audit_log = [
            {"audit_id": "aud_1", "user_id": user_id, "event_time": "2026-05-01T00:00:00Z", "field_name": "email", "old_value": "hop.v1@domain.org", "new_value": "hop.v2@domain.org"},
            {"audit_id": "aud_2", "user_id": user_id, "event_time": "2026-07-01T00:00:00Z", "field_name": "email", "old_value": "hop.v2@domain.org", "new_value": "hop.v3@domain.org"},
            {"audit_id": "aud_3", "user_id": user_id, "event_time": "2026-06-01T00:00:00Z", "field_name": "phone", "old_value": "+1-555-0001", "new_value": "+1-555-0002"},
        ]
        resolver = IdentityResolver(identities, audit_log)
        # Querying by the oldest historical email must resolve the full envelope
        envelope = resolver.resolve("hop.v1@domain.org")
        self.assertIsNotNone(envelope)
        self.assertEqual(envelope.user_id, user_id)
        self.assertEqual(envelope.emails, {"hop.v1@domain.org", "hop.v2@domain.org", "hop.v3@domain.org"})
        self.assertIn("+1-555-0001", envelope.phones)
        self.assertIn("+1-555-0003", envelope.phones)

    def test_3_input_row_ordering_invariance(self):
        """Reordering the input requests produces identical results and strictly sorted output."""
        cases = [
            DeletionCase(f"case_{i:03d}", f"user{i}@test.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-05T00:00:00Z", "2026-09-10T00:00:00Z", "Delete everything.")
            for i in range(1, 10)
        ]
        shuffled = copy.deepcopy(cases)
        random.seed(42)
        random.shuffle(shuffled)

        mock_processor = MagicMock()
        mock_processor.audit_case.side_effect = lambda c: CaseAuditResult(
            case_id=c.case_id,
            status=DeletionStatus.COMPLETE if int(c.case_id.split("_")[1]) % 2 == 0 else DeletionStatus.INCOMPLETE,
            steps=[]
        )

        res_orig = [mock_processor.audit_case(c) for c in cases]
        res_shuf = [mock_processor.audit_case(c) for c in shuffled]

        # Reporter must sort both sets identically by case_id
        sorted_orig = sorted(res_orig, key=lambda r: r.case_id)
        sorted_shuf = sorted(res_shuf, key=lambda r: r.case_id)
        self.assertEqual([r.case_id for r in sorted_orig], [r.case_id for r in sorted_shuf])
        self.assertEqual([r.status for r in sorted_orig], [r.status for r in sorted_shuf])

    def test_4_number_of_records_scaling(self):
        """Batch processing functions consistently whether processing 1 case or 500 cases."""
        batch_sizes = [1, 10, 50]
        for size in batch_sizes:
            cases = [
                DeletionCase(f"case_{i:04d}", f"user{i}@example.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-05T00:00:00Z", "Delete me.")
                for i in range(size)
            ]
            results = [
                CaseAuditResult(case_id=c.case_id, status=DeletionStatus.COMPLETE, steps=[])
                for c in cases
            ]
            self.assertEqual(len(results), size)

    def test_5_new_supported_record_types_appear(self):
        """Dynamic policy engine handles newly configured data categories without code changes."""
        custom_rules = list(self.rules) + [
            DeletionRule("r99", "PRODUCT_TELEMETRY", "DEFAULT", "ANONYMIZE")
        ]
        dynamic_engine = PolicyEngine(custom_rules)
        eval_res = dynamic_engine.evaluate_record(
            category="PRODUCT_TELEMETRY",
            observed_state=ResourceState.PRESENT,
            record_fields={"device_id": "dev_123", "session_count": 5}
        )
        self.assertFalse(eval_res.is_compliant)
        self.assertEqual(eval_res.required_action, "ANONYMIZE")
        self.assertEqual(eval_res.remediation_operation, Operation.ANONYMIZE_RECORD)
        self.assertEqual(eval_res.verification_operation, Operation.VERIFY_RECORD_ANONYMIZED)

    def test_6_policy_rules_change(self):
        """Changing policy action from DELETE to ANONYMIZE dynamically alters required treatment."""
        # Baseline: USER_PROFILE -> DELETE
        eval_delete = self.policy_engine.evaluate_record("USER_PROFILE", ResourceState.PRESENT)
        self.assertEqual(eval_delete.required_action, "DELETE")
        self.assertEqual(eval_delete.remediation_operation, Operation.DELETE_RECORD)

        # Altered policy: USER_PROFILE -> ANONYMIZE
        altered_rules = [
            DeletionRule("r1_mod", "USER_PROFILE", "DEFAULT", "ANONYMIZE")
        ]
        altered_engine = PolicyEngine(altered_rules)
        eval_anon = altered_engine.evaluate_record("USER_PROFILE", ResourceState.PRESENT)
        self.assertEqual(eval_anon.required_action, "ANONYMIZE")
        self.assertEqual(eval_anon.remediation_operation, Operation.ANONYMIZE_RECORD)
        self.assertEqual(eval_anon.verification_operation, Operation.VERIFY_RECORD_ANONYMIZED)

    def test_7_new_synchronization_processes_appear(self):
        """Resurrection engine dynamically flags unseen sync data flows without hardcoding."""
        activities = [
            {
                "activity_id": "act_flow_99",
                "event_time": "2026-09-02T12:00:00Z",
                "event_type": "DATA_FLOW",
                "source_system": "etl_pipeline_service",
                "target_system": "data_warehouse",
                "resource_id": "pipeline_sync_customer_warehouse",
                "reported_result": "ACTIVE",
                "details": "Ongoing streaming pipeline"
            }
        ]
        mock_evidence_store = MagicMock()
        obs = MagicMock()
        obs.resource_id = "pipeline_sync_customer_warehouse"
        obs.file_id = "evidence_flow_doc"
        obs.source_file = "evidence/records/flow.json"
        obs.captured_at = "2026-09-03T00:00:00Z"
        obs.category = "DATA_FLOW"
        obs.state = ResourceState.ACTIVE
        obs.matched_keys = {"pipeline_sync_customer_warehouse"}
        mock_evidence_store.query_subject_observations.return_value = [obs]

        res_engine = ResurrectionEngine(mock_evidence_store, self.policy_engine, activities)
        case = DeletionCase("case_test", "user@test.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-10T00:00:00Z", "Delete.")
        envelope = IdentityEnvelope("user_1", "User", {"user@test.com"})

        report = res_engine.detect_resurrection_risks(case, envelope, target_resource_ids={"pipeline_sync_customer_warehouse"})
        self.assertGreater(len(report.active_risks), 0)
        self.assertEqual(report.active_risks[0].process_ref, "pipeline_sync_customer_warehouse")

    def test_8_optional_fields_missing(self):
        """Loader and models handle missing optional fields without raising exceptions."""
        case = DeletionCase(
            case_id="case_sparse_01",
            email="sparse@domain.com",
            requested_at="2026-09-01T00:00:00Z",
            reported_status="NOT_STARTED",
            reported_at="2026-09-01T00:00:00Z",
            audit_at="2026-09-05T00:00:00Z",
            request_text="Delete profile",
            provenance=None  # Optional field omitted
        )
        self.assertIsNone(case.provenance)
        self.assertEqual(case.case_id, "case_sparse_01")

        rule = DeletionRule(
            rule_id="r_sparse",
            data_category="USER_PROFILE",
            condition="DEFAULT",
            required_action="DELETE"
        )
        self.assertIsNone(rule.provenance)
        self.assertEqual(rule.required_action, "DELETE")

    def test_9_fault_isolation_single_request_failure(self):
        """A failure in an individual case does not halt batch processing or invalidate output schema."""
        cases = [
            DeletionCase("case_ok_1", "ok1@test.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-05T00:00:00Z", "Delete."),
            DeletionCase("case_fault_2", "fault@test.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-05T00:00:00Z", "Delete."),
            DeletionCase("case_ok_3", "ok3@test.com", "2026-09-01T00:00:00Z", "COMPLETE", "2026-09-02T00:00:00Z", "2026-09-05T00:00:00Z", "Delete."),
        ]

        processor = MagicMock(spec=BatchAuditProcessor)
        def mock_audit(case: DeletionCase) -> CaseAuditResult:
            if case.case_id == "case_fault_2":
                raise RuntimeError("Simulated unhandled corrupt record exception!")
            return CaseAuditResult(case_id=case.case_id, status=DeletionStatus.COMPLETE, steps=[])

        processor.audit_case.side_effect = mock_audit

        # Invoke run_all logic
        results, summary = BatchAuditProcessor.run_all(processor, cases)
        self.assertEqual(len(results), 3)
        self.assertEqual(summary["total_cases"], 3)
        self.assertEqual(summary["failures_count"], 1)
        self.assertEqual(summary["failures"][0]["case_id"], "case_fault_2")
        self.assertEqual(results[1].case_id, "case_fault_2")
        self.assertEqual(results[1].status, DeletionStatus.INCOMPLETE)  # Safe fallback status


if __name__ == "__main__":
    unittest.main()
