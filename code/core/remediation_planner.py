"""Remediation planning and dependency-aware step sequencing module.
Generates safe, ordered remediation plans from unresolved findings,
controls resurrection paths before record cleanups, detects dependency cycles,
preserves retained records, and enforces read-only execution safety gates.
"""
from typing import List, Dict, Tuple, Set, Optional
from collections import defaultdict, deque

from code.models import (
    Step, Phase, Operation, ResourceState, DeletionStatus,
    ActionStatus, RemediationAction, RemediationPlan, InvestigationFinding,
    OPERATION_ORDER, PHASE_ORDER
)
from code.core.policy_engine import PolicyEngine
from code.core.errors import DependencyCycleError, UnauthorizedDestructiveActionError
from code.core.logging_utils import get_logger

logger = get_logger("RemediationPlanner")

class RemediationPlanner:
    """Dependency-aware remediation planner and step sequencer."""

    @staticmethod
    def _sort_key(step: Step) -> Tuple[int, int, str, str]:
        p_val = PHASE_ORDER.get(step.phase, 99)
        op_val = OPERATION_ORDER.get(step.operation, 99)
        return (p_val, op_val, step.system_id, step.resource_id)

    @classmethod
    def assemble_case_steps(
        cls,
        findings: List[Step],
        remediations: List[Step],
        verifications: List[Step],
        is_complete: bool
    ) -> List[Step]:
        """Assembles and strictly sequences steps for a case according to official competition rules."""
        if is_complete:
            # COMPLETE cases contain ONLY evidence-backed verification steps
            sorted_verifs = sorted(verifications, key=cls._sort_key)
            result: List[Step] = []
            for idx, s in enumerate(sorted_verifs, start=1):
                result.append(Step(
                    step_no=idx,
                    phase=Phase.VERIFICATION,
                    system_id=s.system_id,
                    resource_id=s.resource_id,
                    operation=s.operation,
                    state=s.state,
                    evidence_id=s.evidence_id
                ))
            return result

        # INCOMPLETE cases contain findings -> remediations -> post-verifications
        sorted_findings = sorted(findings, key=cls._sort_key)
        sorted_remediations = sorted(remediations, key=cls._sort_key)
        sorted_verifications = sorted(verifications, key=cls._sort_key)

        all_steps: List[Step] = []
        cur_no = 1

        for s in sorted_findings:
            all_steps.append(Step(
                step_no=cur_no,
                phase=Phase.FINDING,
                system_id=s.system_id,
                resource_id=s.resource_id,
                operation=s.operation,
                state=s.state,
                evidence_id=s.evidence_id
            ))
            cur_no += 1

        for s in sorted_remediations:
            all_steps.append(Step(
                step_no=cur_no,
                phase=Phase.REMEDIATION,
                system_id=s.system_id,
                resource_id=s.resource_id,
                operation=s.operation,
                state=s.state,
                evidence_id=""  # Remediation must have empty evidence_id
            ))
            cur_no += 1

        for s in sorted_verifications:
            all_steps.append(Step(
                step_no=cur_no,
                phase=Phase.VERIFICATION,
                system_id=s.system_id,
                resource_id=s.resource_id,
                operation=s.operation,
                state=s.state,
                evidence_id=""  # Post-remediation verification must have empty evidence_id
            ))
            cur_no += 1

        return all_steps

    @classmethod
    def plan_remediation_from_finding(cls, finding: Step) -> Step:
        """Determines appropriate remediation operation from finding step."""
        if finding.operation == Operation.REPORT_ACTIVE_DATA_FLOW:
            return Step(step_no=0, phase=Phase.REMEDIATION, system_id=finding.system_id, resource_id=finding.resource_id, operation=Operation.DISABLE_DATA_FLOW, state=ResourceState.DISABLED, evidence_id="")
        elif finding.operation == Operation.REPORT_RESTORE_RISK:
            return Step(step_no=0, phase=Phase.REMEDIATION, system_id=finding.system_id, resource_id=finding.resource_id, operation=Operation.BLOCK_RESTORE, state=ResourceState.BLOCKED, evidence_id="")
        elif finding.operation == Operation.REPORT_REMAINING_RECORD:
            return Step(step_no=0, phase=Phase.REMEDIATION, system_id=finding.system_id, resource_id=finding.resource_id, operation=Operation.DELETE_RECORD, state=ResourceState.ABSENT, evidence_id="")
        elif finding.operation == Operation.REPORT_EXPOSED_PII:
            if finding.system_id == "analytics_platform":
                return Step(step_no=0, phase=Phase.REMEDIATION, system_id=finding.system_id, resource_id=finding.resource_id, operation=Operation.ANONYMIZE_RECORD, state=ResourceState.ANONYMIZED, evidence_id="")
            else:
                return Step(step_no=0, phase=Phase.REMEDIATION, system_id=finding.system_id, resource_id=finding.resource_id, operation=Operation.REDACT_RECORD, state=ResourceState.REDACTED, evidence_id="")
        return Step(step_no=0, phase=Phase.REMEDIATION, system_id=finding.system_id, resource_id=finding.resource_id, operation=Operation.DELETE_RECORD, state=ResourceState.ABSENT, evidence_id="")

    @classmethod
    def plan_verification_from_remediation(cls, remediation: Step) -> Step:
        """Determines required post-remediation verification check."""
        if remediation.operation == Operation.DISABLE_DATA_FLOW:
            return Step(step_no=0, phase=Phase.VERIFICATION, system_id=remediation.system_id, resource_id=remediation.resource_id, operation=Operation.VERIFY_DATA_FLOW_DISABLED, state=ResourceState.DISABLED, evidence_id="")
        elif remediation.operation == Operation.BLOCK_RESTORE:
            return Step(step_no=0, phase=Phase.VERIFICATION, system_id=remediation.system_id, resource_id=remediation.resource_id, operation=Operation.VERIFY_RESTORE_BLOCKED, state=ResourceState.BLOCKED, evidence_id="")
        elif remediation.operation == Operation.DELETE_RECORD:
            return Step(step_no=0, phase=Phase.VERIFICATION, system_id=remediation.system_id, resource_id=remediation.resource_id, operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id="")
        elif remediation.operation == Operation.REDACT_RECORD:
            return Step(step_no=0, phase=Phase.VERIFICATION, system_id=remediation.system_id, resource_id=remediation.resource_id, operation=Operation.VERIFY_RECORD_REDACTED, state=ResourceState.REDACTED, evidence_id="")
        elif remediation.operation == Operation.ANONYMIZE_RECORD:
            return Step(step_no=0, phase=Phase.VERIFICATION, system_id=remediation.system_id, resource_id=remediation.resource_id, operation=Operation.VERIFY_RECORD_ANONYMIZED, state=ResourceState.ANONYMIZED, evidence_id="")
        return Step(step_no=0, phase=Phase.VERIFICATION, system_id=remediation.system_id, resource_id=remediation.resource_id, operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id="")

    def build_plan(
        self,
        case_id: str,
        findings: List[InvestigationFinding],
        policy_engine: PolicyEngine,
        preserved_retained_records: Optional[List[str]] = None
    ) -> RemediationPlan:
        """Constructs a deterministic, dependency-aware remediation plan from findings."""
        actions: List[RemediationAction] = []
        resurrection_action_ids: List[str] = []
        record_cleanup_action_ids: List[str] = []

        # 1. Generate remediation actions for each unresolved finding
        for idx, f in enumerate(findings, start=1):
            finding_id = f"f_{f.system_id}_{f.resource_id}"
            
            # Map operation to remediation
            if f.operation == Operation.REPORT_ACTIVE_DATA_FLOW:
                op = Operation.DISABLE_DATA_FLOW
                tgt_state = ResourceState.DISABLED
                verif_op = Operation.VERIFY_DATA_FLOW_DISABLED
                is_destruct = False
            elif f.operation == Operation.REPORT_RESTORE_RISK:
                op = Operation.BLOCK_RESTORE
                tgt_state = ResourceState.BLOCKED
                verif_op = Operation.VERIFY_RESTORE_BLOCKED
                is_destruct = False
            elif f.operation == Operation.REPORT_REMAINING_RECORD:
                op = Operation.DELETE_RECORD
                tgt_state = ResourceState.ABSENT
                verif_op = Operation.VERIFY_RECORD_ABSENT
                is_destruct = True
            elif f.operation == Operation.REPORT_EXPOSED_PII:
                if f.system_id == "analytics_platform":
                    op = Operation.ANONYMIZE_RECORD
                    tgt_state = ResourceState.ANONYMIZED
                    verif_op = Operation.VERIFY_RECORD_ANONYMIZED
                else:
                    op = Operation.REDACT_RECORD
                    tgt_state = ResourceState.REDACTED
                    verif_op = Operation.VERIFY_RECORD_REDACTED
                is_destruct = False
            else:
                op = Operation.DELETE_RECORD
                tgt_state = ResourceState.ABSENT
                verif_op = Operation.VERIFY_RECORD_ABSENT
                is_destruct = True

            action_id = f"act_{f.system_id}_{f.resource_id}_{op.value.lower()}"

            action = RemediationAction(
                action_id=action_id,
                finding_id=finding_id,
                system_id=f.system_id,
                resource_id=f.resource_id,
                operation=op,
                target_state=tgt_state,
                dependencies=[],
                status=ActionStatus.PROPOSED,
                is_destructive=is_destruct,
                is_authorized=False,
                expected_result=f"Resource {f.resource_id} on {f.system_id} will be transitioned to {tgt_state.value}",
                verification_procedure=f"Execute {verif_op.value} to confirm state {tgt_state.value}",
                verification_operation=verif_op
            )
            actions.append(action)

            if op in [Operation.DISABLE_DATA_FLOW, Operation.BLOCK_RESTORE]:
                resurrection_action_ids.append(action_id)
            else:
                record_cleanup_action_ids.append(action_id)

        # 2. Assign dependency constraints:
        # Rule 8: Resurrection controls (DISABLE_DATA_FLOW, BLOCK_RESTORE) must complete before record cleanup!
        for act in actions:
            if act.action_id in record_cleanup_action_ids:
                act.dependencies.extend(resurrection_action_ids)

        # 3. Detect dependency cycles and compute topological ordering
        ordered_ids, has_cycle, cycle_path = self._topological_sort(actions)

        return RemediationPlan(
            plan_id=f"plan_{case_id}",
            case_id=case_id,
            actions=actions,
            dependency_order=ordered_ids,
            has_cycle=has_cycle,
            cycle_path=cycle_path,
            resurrection_controls_first=bool(resurrection_action_ids),
            preserved_retained_records=preserved_retained_records or []
        )

    def _topological_sort(
        self, actions: List[RemediationAction]
    ) -> Tuple[List[str], bool, List[str]]:
        """Topological sort using Kahn's algorithm with cycle detection."""
        in_degree: Dict[str, int] = {act.action_id: 0 for act in actions}
        adj_list: Dict[str, List[str]] = {act.action_id: [] for act in actions}

        for act in actions:
            for dep in act.dependencies:
                if dep in adj_list:
                    adj_list[dep].append(act.action_id)
                    in_degree[act.action_id] += 1

        queue = deque([act_id for act_id, deg in in_degree.items() if deg == 0])
        ordered: List[str] = []

        while queue:
            node = queue.popleft()
            ordered.append(node)
            for neighbor in adj_list[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(ordered) == len(actions):
            return ordered, False, []

        # Cycle detected
        unresolved = [act_id for act_id, deg in in_degree.items() if deg > 0]
        return ordered, True, unresolved

    def execute_plan(
        self,
        plan: RemediationPlan,
        allow_destructive: bool = False
    ) -> Dict[str, ActionStatus]:
        """Read-only execution engine by default; fails if unauthorized destructive actions are encountered."""
        if plan.has_cycle:
            raise DependencyCycleError(
                f"Cannot execute remediation plan {plan.plan_id} with circular dependency",
                details={"cycle_nodes": plan.cycle_path}
            )

        execution_results: Dict[str, ActionStatus] = {}

        for act_id in plan.dependency_order:
            act = next((a for a in plan.actions if a.action_id == act_id), None)
            if not act:
                continue

            if act.is_destructive and not (allow_destructive or act.is_authorized):
                act.status = ActionStatus.FAILED
                execution_results[act_id] = ActionStatus.FAILED
                raise UnauthorizedDestructiveActionError(
                    f"Destructive action {act.action_id} requires explicit authorization",
                    details={"action_id": act.action_id, "operation": act.operation.value}
                )

            # In read-only audit mode, mark as APPROVED if authorized, or remain PROPOSED
            act.status = ActionStatus.APPROVED if (act.is_authorized or allow_destructive) else ActionStatus.PROPOSED
            execution_results[act_id] = act.status

        return execution_results
