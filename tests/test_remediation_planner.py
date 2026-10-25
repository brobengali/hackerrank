"""Unit test suite for the remediation planner.
Covers:
1. Generation of remediation actions across violation combinations.
2. Action dependency ordering (resurrection controls before record cleanups).
3. Dependency cycle detection and reporting.
4. Preservation of policy-retained records without destructive actions.
5. Read-only safety gates and rejection of unauthorized destructive operations.
6. Action lifecycle status transitions (PROPOSED, APPROVED, FAILED).
"""
import unittest

from code.config import Config
from code.core.loader import DataLoader
from code.core.policy_engine import PolicyEngine
from code.core.remediation_planner import RemediationPlanner
from code.models import (
    Operation, ResourceState, ActionStatus, InvestigationFinding,
    RemediationAction, Step, Phase
)
from code.core.errors import DependencyCycleError, UnauthorizedDestructiveActionError

class TestRemediationPlanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.loader = DataLoader()
        cls.rules = cls.loader.load_deletion_rules(cls.config.deletion_rules_path)
        cls.policy_engine = PolicyEngine(cls.rules)
        cls.planner = RemediationPlanner()

    # =========================================================================
    # 1. Violation Combinations & Stable Action IDs
    # =========================================================================
    def test_plan_generation_different_violation_combinations(self):
        """Generates remediation actions from diverse findings with stable IDs and verification procedures."""
        findings = [
            InvestigationFinding(
                system_id="integration_service",
                resource_id="data_flow_01",
                operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                state=ResourceState.ACTIVE,
                evidence_id="evidence_flow_01",
                category="DATA_FLOW",
                observed_at="2026-09-02T10:00:00Z",
                source_file="evidence_flow_01"
            ),
            InvestigationFinding(
                system_id="backup_service",
                resource_id="backup_01",
                operation=Operation.REPORT_RESTORE_RISK,
                state=ResourceState.ACTIVE,
                evidence_id="evidence_backup_01",
                category="BACKUP_ARCHIVE",
                observed_at="2026-09-02T10:00:00Z",
                source_file="evidence_backup_01"
            ),
            InvestigationFinding(
                system_id="account_service",
                resource_id="account_01",
                operation=Operation.REPORT_REMAINING_RECORD,
                state=ResourceState.PRESENT,
                evidence_id="evidence_acc_01",
                category="USER_PROFILE",
                observed_at="2026-09-02T10:00:00Z",
                source_file="evidence_acc_01"
            ),
            InvestigationFinding(
                system_id="support_platform",
                resource_id="support_01",
                operation=Operation.REPORT_EXPOSED_PII,
                state=ResourceState.PRESENT,
                evidence_id="evidence_sup_01",
                category="SUPPORT_MESSAGE",
                observed_at="2026-09-02T10:00:00Z",
                source_file="evidence_sup_01"
            ),
            InvestigationFinding(
                system_id="analytics_platform",
                resource_id="analytics_01",
                operation=Operation.REPORT_EXPOSED_PII,
                state=ResourceState.PRESENT,
                evidence_id="evidence_ana_01",
                category="ANALYTICS_PROFILE",
                observed_at="2026-09-02T10:00:00Z",
                source_file="evidence_ana_01"
            ),
        ]

        plan = self.planner.build_plan("case_test_combo", findings, self.policy_engine)
        self.assertEqual(len(plan.actions), 5)
        self.assertFalse(plan.has_cycle)

        # Check action mappings and stable IDs
        ops = {a.resource_id: a.operation for a in plan.actions}
        self.assertEqual(ops["data_flow_01"], Operation.DISABLE_DATA_FLOW)
        self.assertEqual(ops["backup_01"], Operation.BLOCK_RESTORE)
        self.assertEqual(ops["account_01"], Operation.DELETE_RECORD)
        self.assertEqual(ops["support_01"], Operation.REDACT_RECORD)
        self.assertEqual(ops["analytics_01"], Operation.ANONYMIZE_RECORD)

        for a in plan.actions:
            self.assertTrue(a.action_id.startswith(f"act_{a.system_id}_{a.resource_id}_"))
            self.assertEqual(a.finding_id, f"f_{a.system_id}_{a.resource_id}")
            self.assertEqual(a.status, ActionStatus.PROPOSED)
            self.assertGreater(len(a.expected_result), 0)
            self.assertGreater(len(a.verification_procedure), 0)

    # =========================================================================
    # 2. Dependency Ordering (Resurrection Controls First)
    # =========================================================================
    def test_resurrection_controls_first_dependency(self):
        """Resurrection path actions must precede dependent record cleanups in topological ordering."""
        findings = [
            InvestigationFinding(
                system_id="account_service",
                resource_id="account_target",
                operation=Operation.REPORT_REMAINING_RECORD,
                state=ResourceState.PRESENT,
                evidence_id="ev_acc",
                category="USER_PROFILE",
                observed_at="2026-09-02T10:00:00Z",
                source_file="ev_acc"
            ),
            InvestigationFinding(
                system_id="integration_service",
                resource_id="data_flow_source",
                operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                state=ResourceState.ACTIVE,
                evidence_id="ev_flow",
                category="DATA_FLOW",
                observed_at="2026-09-02T10:00:00Z",
                source_file="ev_flow"
            ),
        ]

        plan = self.planner.build_plan("case_test_dep", findings, self.policy_engine)
        self.assertTrue(plan.resurrection_controls_first)
        
        # In topological order, data flow action MUST appear before account deletion
        flow_idx = plan.dependency_order.index("act_integration_service_data_flow_source_disable_data_flow")
        acc_idx = plan.dependency_order.index("act_account_service_account_target_delete_record")
        self.assertLess(flow_idx, acc_idx, "Resurrection controls must execute before dependent record deletion")

    # =========================================================================
    # 3. Dependency Cycles Detection
    # =========================================================================
    def test_dependency_cycle_detection(self):
        """Circular dependencies are detected and prevent execution."""
        act_a = RemediationAction(
            action_id="act_A",
            finding_id="f_A",
            system_id="sys_A",
            resource_id="res_A",
            operation=Operation.DELETE_RECORD,
            target_state=ResourceState.ABSENT,
            dependencies=["act_B"]
        )
        act_b = RemediationAction(
            action_id="act_B",
            finding_id="f_B",
            system_id="sys_B",
            resource_id="res_B",
            operation=Operation.DELETE_RECORD,
            target_state=ResourceState.ABSENT,
            dependencies=["act_A"]
        )

        plan = self.planner.build_plan("case_cycle", [], self.policy_engine)
        plan.actions = [act_a, act_b]
        ordered, has_cycle, cycle_path = self.planner._topological_sort([act_a, act_b])

        self.assertTrue(has_cycle)
        self.assertIn("act_A", cycle_path)
        self.assertIn("act_B", cycle_path)

        plan.has_cycle = True
        plan.cycle_path = cycle_path

        with self.assertRaises(DependencyCycleError):
            self.planner.execute_plan(plan)

    # =========================================================================
    # 4. Retained Records Preservation
    # =========================================================================
    def test_retained_records_preserved(self):
        """Retained records required by policy are preserved and not assigned deletion actions."""
        plan = self.planner.build_plan(
            case_id="case_retained",
            findings=[],
            policy_engine=self.policy_engine,
            preserved_retained_records=["audit_record_999", "legal_hold_123"]
        )
        self.assertEqual(len(plan.actions), 0)
        self.assertIn("audit_record_999", plan.preserved_retained_records)
        self.assertIn("legal_hold_123", plan.preserved_retained_records)

    # =========================================================================
    # 5. Read-Only Safety Gates & Failed Remediation
    # =========================================================================
    def test_unauthorized_destructive_action_fails(self):
        """Destructive action without explicit authorization raises UnauthorizedDestructiveActionError."""
        finding = InvestigationFinding(
            system_id="account_service",
            resource_id="account_prod_01",
            operation=Operation.REPORT_REMAINING_RECORD,
            state=ResourceState.PRESENT,
            evidence_id="ev_01",
            category="USER_PROFILE",
            observed_at="2026-09-02T10:00:00Z",
            source_file="ev_01"
        )
        plan = self.planner.build_plan("case_test_safety", [finding], self.policy_engine)
        
        # Attempting execution in default read-only mode (without authorization)
        with self.assertRaises(UnauthorizedDestructiveActionError):
            self.planner.execute_plan(plan, allow_destructive=False)

        # Confirm action was marked as FAILED
        act = plan.actions[0]
        self.assertEqual(act.status, ActionStatus.FAILED)

    def test_authorized_action_approval(self):
        """Explicitly authorized action transitions to APPROVED state."""
        finding = InvestigationFinding(
            system_id="account_service",
            resource_id="account_prod_02",
            operation=Operation.REPORT_REMAINING_RECORD,
            state=ResourceState.PRESENT,
            evidence_id="ev_02",
            category="USER_PROFILE",
            observed_at="2026-09-02T10:00:00Z",
            source_file="ev_02"
        )
        plan = self.planner.build_plan("case_test_auth", [finding], self.policy_engine)
        plan.actions[0].is_authorized = True

        results = self.planner.execute_plan(plan, allow_destructive=True)
        self.assertEqual(results[plan.actions[0].action_id], ActionStatus.APPROVED)
        self.assertEqual(plan.actions[0].status, ActionStatus.APPROVED)

if __name__ == "__main__":
    unittest.main()
