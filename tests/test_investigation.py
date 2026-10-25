"""Unit test suite for cross-system record investigation and event reconstruction.
Covers:
1. Residual records that should have been deleted (REPORT_REMAINING_RECORD).
2. Historical identifiers remaining in records even when current email is absent.
3. Prohibited hashes exposed in active records.
4. Permitted account tombstones (stable user_id permitted; direct PII prohibited).
5. Incomplete event histories and discrepancies between workflow claims and evidence facts.
6. Resurrection paths (active data flows and restore risks).
"""
import unittest
from pathlib import Path

from code.config import Config
from code.core.loader import DataLoader
from code.core.policy_engine import PolicyEngine
from code.core.evidence_store import EvidenceStore, EvidenceObservation
from code.core.investigator import CrossSystemInvestigator
from code.models import (
    IdentityEnvelope, DeletionCase, Operation, ResourceState,
    HistoricalEvent, InvestigationFinding
)

class TestCrossSystemInvestigator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.loader = DataLoader()
        cls.rules = cls.loader.load_deletion_rules(cls.config.deletion_rules_path)
        cls.manifest = cls.loader.load_evidence_manifest(cls.config.evidence_files_path)
        cls.system_activity = cls.loader.load_system_activity(cls.config.system_activity_path)
        cls.policy_engine = PolicyEngine(cls.rules)
        cls.evidence_store = EvidenceStore(cls.config.dataset_dir, cls.manifest)
        cls.investigator = CrossSystemInvestigator(
            evidence_store=cls.evidence_store,
            policy_engine=cls.policy_engine,
            system_activities=cls.system_activity
        )

    # =========================================================================
    # 1. Residual Records (REPORT_REMAINING_RECORD)
    # =========================================================================
    def test_residual_record_detection(self):
        """Detects a residual customer record that should have been deleted."""
        envelope = IdentityEnvelope(
            user_id="user_residual_01",
            canonical_name="Residual User",
            emails={"residual@example.com"},
            phones={"+15551234567"},
            email_hashes={"a" * 64}
        )
        case = DeletionCase(
            case_id="case_test_residual",
            email="residual@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Please delete all my personal data."
        )

        # Inject an observation of an undeleted account profile
        obs = EvidenceObservation(
            file_id="evidence_test_01",
            captured_at="2026-09-02T10:00:00Z",
            system_id="account_service",
            resource_id="account_9999",
            category="USER_PROFILE",
            state=ResourceState.PRESENT,
            matched_keys={"user_residual_01", "residual@example.com"},
            details={"email": "residual@example.com"}
        )
        self.investigator.evidence_store.observations.append(obs)

        report = self.investigator.investigate(case, envelope, target_resource_ids={"account_9999"})
        self.assertGreater(len(report.findings), 0)

        residual_finding = next((f for f in report.findings if f.resource_id == "account_9999"), None)
        self.assertIsNotNone(residual_finding)
        self.assertEqual(residual_finding.operation, Operation.REPORT_REMAINING_RECORD)
        self.assertEqual(residual_finding.state, ResourceState.PRESENT)
        self.assertEqual(residual_finding.evidence_id, "evidence_test_01")
        self.assertTrue(residual_finding.is_fact)

    # =========================================================================
    # 2. Historical Identifiers Detection
    # =========================================================================
    def test_historical_identifier_detected_when_current_email_absent(self):
        """Catches a record that still contains the user's historical email even if current email was removed."""
        envelope = IdentityEnvelope(
            user_id="user_hist_02",
            canonical_name="Historical User",
            emails={"current.email@example.com", "old.historical@example.com"},
            phones=set(),
            email_hashes=set()
        )
        case = DeletionCase(
            case_id="case_test_hist",
            email="current.email@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my account permanently."
        )

        obs = EvidenceObservation(
            file_id="evidence_test_hist",
            captured_at="2026-09-02T10:00:00Z",
            system_id="support_platform",
            resource_id="support_8888",
            category="SUPPORT_ATTACHMENT",
            state=ResourceState.PRESENT,
            matched_keys={"old.historical@example.com"},
            details={"contact_email": "old.historical@example.com"}
        )
        self.investigator.evidence_store.observations.append(obs)

        report = self.investigator.investigate(case, envelope)
        hist_finding = next((f for f in report.findings if f.resource_id == "support_8888"), None)
        self.assertIsNotNone(hist_finding)
        self.assertEqual(hist_finding.operation, Operation.REPORT_REMAINING_RECORD)
        self.assertIn("email:old.historical@example.com", hist_finding.prohibited_identifiers_found)

    # =========================================================================
    # 3. Prohibited Email Hashes
    # =========================================================================
    def test_prohibited_hash_detected(self):
        """Catches exposed prohibited email hashes."""
        target_hash = "f" * 64
        envelope = IdentityEnvelope(
            user_id="user_hash_03",
            canonical_name="Hash User",
            emails={"user@hash.com"},
            phones=set(),
            email_hashes={target_hash}
        )
        case = DeletionCase(
            case_id="case_test_hash",
            email="user@hash.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my data."
        )

        obs = EvidenceObservation(
            file_id="evidence_test_hash",
            captured_at="2026-09-02T10:00:00Z",
            system_id="marketing_platform",
            resource_id="audience_7777",
            category="MARKETING_PROFILE",
            state=ResourceState.PRESENT,
            matched_keys={target_hash},
            details={"email_hash": target_hash}
        )
        self.investigator.evidence_store.observations.append(obs)

        report = self.investigator.investigate(case, envelope)
        hash_finding = next((f for f in report.findings if f.resource_id == "audience_7777"), None)
        self.assertIsNotNone(hash_finding)
        self.assertIn(f"hash:{target_hash}", hash_finding.prohibited_identifiers_found)

    # =========================================================================
    # 4. Permitted Account Tombstones vs Violating Tombstones
    # =========================================================================
    def test_permitted_account_tombstone_not_flagged(self):
        """A tombstone preserving only the stable user_id with PII removed is NOT a violation."""
        envelope = IdentityEnvelope(
            user_id="user_tomb_04",
            canonical_name="Tombstone User",
            emails={"tomb@user.com"},
            phones=set(),
            email_hashes=set()
        )
        case = DeletionCase(
            case_id="case_test_tomb_ok",
            email="tomb@user.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my account."
        )

        # Compliant tombstone: state=REDACTED, no exposed PII, only user_id reference
        obs = EvidenceObservation(
            file_id="evidence_test_tomb_ok",
            captured_at="2026-09-02T10:00:00Z",
            system_id="identity_service",
            resource_id="tombstone_04",
            category="ACCOUNT_TOMBSTONE",
            state=ResourceState.REDACTED,
            matched_keys={"user_tomb_04"},
            has_exposed_pii=False,
            details={"subject_reference": "user_tomb_04"}
        )
        self.investigator.evidence_store.observations.append(obs)

        report = self.investigator.investigate(case, envelope, target_resource_ids={"tombstone_04"})
        tomb_findings = [f for f in report.findings if f.resource_id == "tombstone_04"]
        self.assertEqual(len(tomb_findings), 0, "Compliant tombstone must not produce findings")

    def test_violating_account_tombstone_with_direct_pii_flagged(self):
        """A tombstone that still contains direct PII (e.g. email) IS flagged as REPORT_EXPOSED_PII."""
        envelope = IdentityEnvelope(
            user_id="user_tomb_05",
            canonical_name="Violating Tombstone",
            emails={"bad.tomb@user.com"},
            phones=set(),
            email_hashes=set()
        )
        case = DeletionCase(
            case_id="case_test_tomb_bad",
            email="bad.tomb@user.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my account."
        )

        obs = EvidenceObservation(
            file_id="evidence_test_tomb_bad",
            captured_at="2026-09-02T10:00:00Z",
            system_id="identity_service",
            resource_id="tombstone_05",
            category="ACCOUNT_TOMBSTONE",
            state=ResourceState.PRESENT,
            matched_keys={"user_tomb_05", "bad.tomb@user.com"},
            has_exposed_pii=True,
            details={"subject_reference": "user_tomb_05", "email": "bad.tomb@user.com"}
        )
        self.investigator.evidence_store.observations.append(obs)

        report = self.investigator.investigate(case, envelope, target_resource_ids={"tombstone_05"})
        tomb_finding = next((f for f in report.findings if f.resource_id == "tombstone_05"), None)
        self.assertIsNotNone(tomb_finding)
        self.assertEqual(tomb_finding.operation, Operation.REPORT_EXPOSED_PII)

    # =========================================================================
    # 5. Incomplete Event Histories & Evidence Gaps
    # =========================================================================
    def test_reconstruct_events_and_detect_gaps(self):
        """Reconstructs historical events and flags discrepancy between claimed workflow and evidence."""
        case = DeletionCase(
            case_id="case_test_gap",
            email="gap@example.com",
            requested_at="2026-09-10T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-10T12:00:00Z",
            audit_at="2026-09-15T12:00:00Z",
            request_text="Delete my account completely."
        )
        envelope = IdentityEnvelope(
            user_id="user_gap_06",
            canonical_name="Gap User",
            emails={"gap@example.com"}
        )

        # Inject fake activity event claiming success
        self.investigator.deletion_worker_activities.append({
            "activity_id": "act_test_gap_1",
            "event_time": "2026-09-10T11:00:00Z",
            "event_type": "DELETE_RECORD",
            "source_system": "deletion_worker",
            "target_system": "account_service",
            "resource_id": "account_gap_99",
            "reported_result": "SUCCESS",
            "details": "Deleted account"
        })

        # But evidence observation shows the account is still PRESENT
        obs = EvidenceObservation(
            file_id="evidence_test_gap",
            captured_at="2026-09-12T10:00:00Z",
            system_id="account_service",
            resource_id="account_gap_99",
            category="USER_PROFILE",
            state=ResourceState.PRESENT,
            matched_keys={"user_gap_06", "gap@example.com"}
        )
        self.investigator.evidence_store.observations.append(obs)

        report = self.investigator.investigate(case, envelope, target_resource_ids={"account_gap_99"})
        self.assertGreater(len(report.reconstructed_events), 0)
        self.assertEqual(report.reconstructed_events[0].event_id, "act_test_gap_1")
        self.assertTrue(report.reconstructed_events[0].is_claim)

        # Verify discrepancy gap detection
        self.assertGreater(len(report.evidence_gaps), 0)
        self.assertTrue(any("Discrepancy" in gap for gap in report.evidence_gaps))

    # =========================================================================
    # 7. Cross-Subject Contamination & Tie-Breaker Isolation Tests
    # =========================================================================
    def test_cross_subject_email_isolation_prevents_contamination(self):
        """Observations containing emails belonging to another subject are isolated even if in additional_resource_ids."""
        subject = IdentityEnvelope(
            user_id="user_subj_01",
            canonical_name="Target Subject",
            emails={"target.subject@example.com"}
        )
        obs_other = EvidenceObservation(
            file_id="evidence_test_iso_1",
            captured_at="2026-09-01T10:00:00Z",
            system_id="search_service",
            resource_id="search_shared_res",
            category="SEARCH_INDEX_ENTRY",
            state=ResourceState.PRESENT,
            matched_keys={"search_shared_res", "unrelated.person@example.com"}
        )
        self.evidence_store.observations.append(obs_other)

        matched = self.evidence_store.query_subject_observations(
            identity=subject,
            audit_at="2026-09-15T12:00:00Z",
            additional_resource_ids={"search_shared_res"}
        )
        # Must NOT match because the observation explicitly contains an unrelated email
        self.assertFalse(any(o.resource_id == "search_shared_res" for o in matched))

    def test_same_timestamp_observation_tie_breaker(self):
        """When two observations for the same resource exist at the same captured_at, non-compliant state wins."""
        subject = IdentityEnvelope(
            user_id="user_tie_01",
            canonical_name="Tie Subject",
            emails={"tie.user@example.com"}
        )
        obs_compliant = EvidenceObservation(
            file_id="evidence_test_tie",
            captured_at="2026-09-02T10:00:00Z",
            system_id="support_platform",
            resource_id="support_tie_99",
            category="SUPPORT_MESSAGE",
            state=ResourceState.REDACTED,
            has_exposed_pii=False,
            matched_keys={"tie.user@example.com"}
        )
        obs_violation = EvidenceObservation(
            file_id="evidence_test_tie",
            captured_at="2026-09-02T10:00:00Z",
            system_id="support_platform",
            resource_id="support_tie_99",
            category="SUPPORT_MESSAGE",
            state=ResourceState.PRESENT,
            has_exposed_pii=True,
            matched_keys={"tie.user@example.com"}
        )
        self.investigator.evidence_store.observations.extend([obs_compliant, obs_violation])

        case = DeletionCase(
            case_id="case_test_tie",
            email="tie.user@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my support data."
        )
        report = self.investigator.investigate(case, subject, target_resource_ids={"support_tie_99"})
        obs_chosen = report.observed_resources.get(("support_platform", "support_tie_99"))
        self.assertIsNotNone(obs_chosen)
        self.assertTrue(obs_chosen.has_exposed_pii)
        self.assertEqual(obs_chosen.state, ResourceState.PRESENT)


if __name__ == "__main__":
    unittest.main()
