"""Unit test suite for the resurrection detection engine.
Covers:
1. Active synchronization and data flows (REPORT_ACTIVE_DATA_FLOW, DISABLE_DATA_FLOW).
2. Active backup restore risks (REPORT_RESTORE_RISK, BLOCK_RESTORE).
3. Controlled/inactive processes (DISABLED, BLOCKED) with verified controls.
4. Historical imports and synchronizations that do not cause active risks.
5. Unknown process states and missing process evidence requiring verification.
"""
import unittest
from pathlib import Path

from code.config import Config
from code.core.loader import DataLoader
from code.core.policy_engine import PolicyEngine
from code.core.evidence_store import EvidenceStore, EvidenceObservation
from code.core.resurrection import ResurrectionEngine
from code.models import (
    IdentityEnvelope, DeletionCase, Operation, ResourceState,
    ProcessStatus, ResurrectionRisk
)

class TestResurrectionEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.loader = DataLoader()
        cls.rules = cls.loader.load_deletion_rules(cls.config.deletion_rules_path)
        cls.manifest = cls.loader.load_evidence_manifest(cls.config.evidence_files_path)
        cls.system_activity = cls.loader.load_system_activity(cls.config.system_activity_path)
        cls.policy_engine = PolicyEngine(cls.rules)
        cls.evidence_store = EvidenceStore(cls.config.dataset_dir, cls.manifest)
        cls.engine = ResurrectionEngine(
            evidence_store=cls.evidence_store,
            policy_engine=cls.policy_engine,
            system_activities=cls.system_activity
        )

    # =========================================================================
    # 1. Active Synchronization & Data Flows
    # =========================================================================
    def test_active_data_flow_resurrection(self):
        """Active data flow is detected as a confirmed risk capable of recreating data."""
        case = DeletionCase(
            case_id="case_test_flow",
            email="flow.user@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete all my information."
        )
        envelope = IdentityEnvelope(
            user_id="user_flow_01",
            canonical_name="Flow User",
            emails={"flow.user@example.com"}
        )

        obs = EvidenceObservation(
            file_id="evidence_test_flow",
            captured_at="2026-09-02T10:00:00Z",
            system_id="integration_service",
            resource_id="data_flow_999",
            category="DATA_FLOW",
            state=ResourceState.ACTIVE,
            matched_keys={"user_flow_01", "flow.user@example.com"}
        )
        self.engine.evidence_store.observations.append(obs)

        report = self.engine.detect_resurrection_risks(case, envelope, target_resource_ids={"data_flow_999"})
        self.assertGreater(len(report.active_risks), 0)

        flow_risk = next((r for r in report.active_risks if r.process_ref == "data_flow_999"), None)
        self.assertIsNotNone(flow_risk)
        self.assertEqual(flow_risk.status, ProcessStatus.ACTIVE)
        self.assertTrue(flow_risk.can_recreate_data)
        self.assertTrue(flow_risk.is_confirmed_active)
        self.assertEqual(flow_risk.required_remediation, Operation.DISABLE_DATA_FLOW)
        self.assertEqual(flow_risk.target_remediation_state, ResourceState.DISABLED)
        self.assertEqual(flow_risk.verification_requirement, Operation.VERIFY_DATA_FLOW_DISABLED)

        # Convert to investigation findings
        findings = self.engine.to_investigation_findings(report)
        flow_finding = next((f for f in findings if f.resource_id == "data_flow_999"), None)
        self.assertIsNotNone(flow_finding)
        self.assertEqual(flow_finding.operation, Operation.REPORT_ACTIVE_DATA_FLOW)
        self.assertEqual(flow_finding.state, ResourceState.ACTIVE)

    # =========================================================================
    # 2. Active Backup Restore Risk
    # =========================================================================
    def test_active_backup_restore_risk(self):
        """Active restore risk is detected when archive restore is allowed."""
        case = DeletionCase(
            case_id="case_test_restore",
            email="restore.user@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my account permanently."
        )
        envelope = IdentityEnvelope(
            user_id="user_restore_02",
            canonical_name="Restore User",
            emails={"restore.user@example.com"}
        )

        obs = EvidenceObservation(
            file_id="evidence_test_restore",
            captured_at="2026-09-02T10:00:00Z",
            system_id="backup_service",
            resource_id="backup_888",
            category="BACKUP_ARCHIVE",
            state=ResourceState.ACTIVE,
            matched_keys={"user_restore_02", "restore.user@example.com"}
        )
        self.engine.evidence_store.observations.append(obs)

        report = self.engine.detect_resurrection_risks(case, envelope, target_resource_ids={"backup_888"})
        self.assertGreater(len(report.active_risks), 0)

        restore_risk = next((r for r in report.active_risks if r.process_ref == "backup_888"), None)
        self.assertIsNotNone(restore_risk)
        self.assertEqual(restore_risk.status, ProcessStatus.ACTIVE)
        self.assertTrue(restore_risk.can_recreate_data)
        self.assertEqual(restore_risk.required_remediation, Operation.BLOCK_RESTORE)
        self.assertEqual(restore_risk.target_remediation_state, ResourceState.BLOCKED)
        self.assertEqual(restore_risk.verification_requirement, Operation.VERIFY_RESTORE_BLOCKED)

        findings = self.engine.to_investigation_findings(report)
        restore_finding = next((f for f in findings if f.resource_id == "backup_888"), None)
        self.assertIsNotNone(restore_finding)
        self.assertEqual(restore_finding.operation, Operation.REPORT_RESTORE_RISK)

    # =========================================================================
    # 3. Controlled/Inactive Processes
    # =========================================================================
    def test_controlled_processes_inactive(self):
        """Disabled data flows and blocked restores are recognized as controlled processes."""
        case = DeletionCase(
            case_id="case_test_controlled",
            email="controlled.user@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Delete my data."
        )
        envelope = IdentityEnvelope(
            user_id="user_controlled_03",
            canonical_name="Controlled User",
            emails={"controlled.user@example.com"}
        )

        obs_flow = EvidenceObservation(
            file_id="evidence_test_flow_off",
            captured_at="2026-09-02T10:00:00Z",
            system_id="integration_service",
            resource_id="data_flow_777",
            category="DATA_FLOW",
            state=ResourceState.DISABLED,
            matched_keys={"user_controlled_03"}
        )
        obs_backup = EvidenceObservation(
            file_id="evidence_test_backup_off",
            captured_at="2026-09-02T10:00:00Z",
            system_id="backup_service",
            resource_id="backup_777",
            category="BACKUP_ARCHIVE",
            state=ResourceState.BLOCKED,
            matched_keys={"user_controlled_03"}
        )
        self.engine.evidence_store.observations.extend([obs_flow, obs_backup])

        report = self.engine.detect_resurrection_risks(case, envelope, target_resource_ids={"data_flow_777", "backup_777"})
        self.assertEqual(len(report.active_risks), 0)
        self.assertGreaterEqual(len(report.controlled_processes), 2)

        controlled_flow = next((r for r in report.controlled_processes if r.process_ref == "data_flow_777"), None)
        self.assertIsNotNone(controlled_flow)
        self.assertEqual(controlled_flow.status, ProcessStatus.INACTIVE)
        self.assertFalse(controlled_flow.can_recreate_data)
        self.assertGreater(len(controlled_flow.existing_controls), 0)

        controlled_backup = next((r for r in report.controlled_processes if r.process_ref == "backup_777"), None)
        self.assertIsNotNone(controlled_backup)
        self.assertEqual(controlled_backup.status, ProcessStatus.INACTIVE)
        self.assertFalse(controlled_backup.can_recreate_data)

        # Confirm no violation findings emitted for controlled processes
        findings = self.engine.to_investigation_findings(report)
        self.assertEqual(len(findings), 0)

    # =========================================================================
    # 4. Historical Synchronizations and Imports
    # =========================================================================
    def test_historical_synchronization(self):
        """Historical sync events completed prior to deletion request do not cause active risks."""
        case = DeletionCase(
            case_id="case_test_hist_sync",
            email="hist.sync@example.com",
            requested_at="2026-09-10T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-10T12:00:00Z",
            audit_at="2026-09-15T12:00:00Z",
            request_text="Delete my account."
        )
        envelope = IdentityEnvelope(
            user_id="user_hist_sync_04",
            canonical_name="Hist Sync User",
            emails={"hist.sync@example.com"}
        )

        # Inject historical sync event that completed prior to requested_at
        self.engine.system_activities.append({
            "activity_id": "act_hist_sync_1",
            "event_time": "2026-09-01T08:00:00Z",
            "event_type": "SYNC_RECORD",
            "source_system": "account_service",
            "target_system": "analytics_platform",
            "resource_id": "analytics_hist_1",
            "reported_result": "SUCCESS",
            "details": "Customer profile sync"
        })
        self.engine._index_activity_streams()

        report = self.engine.detect_resurrection_risks(case, envelope, target_resource_ids={"analytics_hist_1"})
        hist_sync = next((r for r in report.historical_processes if r.relevant_records == ["analytics_hist_1"]), None)
        self.assertIsNotNone(hist_sync)
        self.assertEqual(hist_sync.status, ProcessStatus.HISTORICAL)
        self.assertFalse(hist_sync.can_recreate_data)
        self.assertFalse(hist_sync.is_confirmed_active)

    # =========================================================================
    # 5. Unknown Process States & Missing Evidence
    # =========================================================================
    def test_unknown_process_state_missing_evidence(self):
        """Claimed active connector check without corroborating evidence is flagged as UNKNOWN uncertainty."""
        case = DeletionCase(
            case_id="case_test_unknown",
            email="unknown.user@example.com",
            requested_at="2026-09-10T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-10T12:00:00Z",
            audit_at="2026-09-15T12:00:00Z",
            request_text="Please delete my account."
        )
        envelope = IdentityEnvelope(
            user_id="user_unknown_05",
            canonical_name="Unknown User",
            emails={"unknown.user@example.com"}
        )

        # Inject activity claiming connector remains enabled, with NO evidence file
        self.engine.system_activities.append({
            "activity_id": "act_unknown_check_1",
            "event_time": "2026-09-10T11:30:00Z",
            "event_type": "CHECK_DATA_FLOW",
            "source_system": "deletion_worker",
            "target_system": "integration_service",
            "resource_id": "data_flow_unverified_99",
            "reported_result": "SUCCESS",
            "details": "Connector status check confirmed that data flow remains enabled."
        })
        self.engine._index_activity_streams()

        report = self.engine.detect_resurrection_risks(case, envelope, target_resource_ids={"data_flow_unverified_99"})
        self.assertGreater(len(report.uncertain_processes), 0)

        uncertain = next((r for r in report.uncertain_processes if r.process_ref == "data_flow_unverified_99"), None)
        self.assertIsNotNone(uncertain)
        self.assertEqual(uncertain.status, ProcessStatus.UNKNOWN)
        self.assertTrue(uncertain.can_recreate_data)
        self.assertEqual(uncertain.required_remediation, Operation.DISABLE_DATA_FLOW)
        self.assertEqual(uncertain.verification_requirement, Operation.VERIFY_DATA_FLOW_DISABLED)

if __name__ == "__main__":
    unittest.main()
