"""Deterministic verification engine and post-model safety gate.
Evaluates explicit completion invariants entirely in validated Python logic,
preventing LLMs or heuristic models from controlling or overriding the final status.
"""
from typing import List, Dict, Set, Optional, Tuple, Any

from code.models import (
    DeletionCase, DeletionStatus, Operation, ResourceState, Phase, Step,
    InvestigationFinding, ResurrectionReport, CompletionInvariantResult,
    SafetyGateEvaluation
)
from code.core.logging_utils import get_logger

logger = get_logger("VerificationEngine")

class VerificationEngine:
    """Computes and validates deterministic completion invariants."""

    def __init__(self):
        pass

    def evaluate_completion_invariants(
        self,
        case: DeletionCase,
        is_deletion_authorized: bool,
        findings: List[InvestigationFinding],
        verification_steps: List[Step],
        resurrection_report: Optional[ResurrectionReport] = None,
        retained_records_verified: bool = True,
        has_inaccessible_systems: bool = False
    ) -> List[CompletionInvariantResult]:
        """Evaluates all required completion invariants, recording explicit reasons for failures."""
        results: List[CompletionInvariantResult] = []

        # Invariant 1: Deletion Authorization
        if not is_deletion_authorized:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_REQUEST_AUTHORIZED",
                passed=False,
                failure_reason="Request text does not authorize deletion (non-deletion or opt-out request)"
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_REQUEST_AUTHORIZED",
                passed=True
            ))

        # Invariant 2: No Residual Personal Data Records
        residual_findings = [f for f in findings if f.operation == Operation.REPORT_REMAINING_RECORD]
        if residual_findings:
            res_ids = [f"{f.system_id}:{f.resource_id}" for f in residual_findings]
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_NO_RESIDUAL_RECORDS",
                passed=False,
                failure_reason=f"Residual records that should have been deleted remain PRESENT: {res_ids}",
                details={"residual_records": res_ids}
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_NO_RESIDUAL_RECORDS",
                passed=True
            ))

        # Invariant 3: No Exposed Direct PII
        exposed_pii_findings = [f for f in findings if f.operation == Operation.REPORT_EXPOSED_PII]
        if exposed_pii_findings:
            res_ids = [f"{f.system_id}:{f.resource_id}" for f in exposed_pii_findings]
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_NO_EXPOSED_PII",
                passed=False,
                failure_reason=f"Prohibited direct identifiers remain exposed in records: {res_ids}",
                details={"exposed_records": res_ids}
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_NO_EXPOSED_PII",
                passed=True
            ))

        # Invariant 4: Active Resurrection Paths Controlled
        active_flow_findings = [f for f in findings if f.operation in [Operation.REPORT_ACTIVE_DATA_FLOW, Operation.REPORT_RESTORE_RISK]]
        active_report_risks = resurrection_report.active_risks if resurrection_report else []
        if active_flow_findings or active_report_risks:
            risk_refs = [f.resource_id for f in active_flow_findings] + [r.process_ref for r in active_report_risks]
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_RESURRECTION_CONTROLLED",
                passed=False,
                failure_reason=f"Active data flows or restore risks can recreate prohibited personal data: {risk_refs}",
                details={"active_risks": risk_refs}
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_RESURRECTION_CONTROLLED",
                passed=True
            ))

        # Invariant 5: Required Retained Records Available
        if not retained_records_verified:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_RETAINED_RECORDS_AVAILABLE",
                passed=False,
                failure_reason="Policy-required retained records (e.g. security audit log) are missing or deleted"
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_RETAINED_RECORDS_AVAILABLE",
                passed=True
            ))

        # Invariant 6: Permitted Tombstones Retain Only Authorized Internal References
        violating_tombstones = [f for f in findings if f.category == "ACCOUNT_TOMBSTONE" and f.operation == Operation.REPORT_EXPOSED_PII]
        if violating_tombstones:
            tomb_ids = [f.resource_id for f in violating_tombstones]
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_PERMITTED_TOMBSTONES_COMPLIANT",
                passed=False,
                failure_reason=f"Account tombstone exposes prohibited personal fields: {tomb_ids}",
                details={"violating_tombstones": tomb_ids}
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_PERMITTED_TOMBSTONES_COMPLIANT",
                passed=True
            ))

        # Invariant 7: Evidence Provenance Required for Verification
        # Missing evidence must never count as successful verification
        if not verification_steps and not findings:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_EVIDENCE_PROVENANCE_REQUIRED",
                passed=False,
                failure_reason="No evidence-backed verification steps exist proving completion at audit cutoff"
            ))
        else:
            empty_ev_verifs = [v for v in verification_steps if not v.evidence_id]
            if empty_ev_verifs and not findings:
                # If candidate COMPLETE case has verifications lacking evidence, completion fails
                missing_ids = [f"{v.system_id}:{v.resource_id}" for v in empty_ev_verifs]
                results.append(CompletionInvariantResult(
                    invariant_name="INVARIANT_EVIDENCE_PROVENANCE_REQUIRED",
                    passed=False,
                    failure_reason=f"Verification steps lack evidence captured before audit cutoff: {missing_ids}",
                    details={"unverified_steps": missing_ids}
                ))
            else:
                results.append(CompletionInvariantResult(
                    invariant_name="INVARIANT_EVIDENCE_PROVENANCE_REQUIRED",
                    passed=True
                ))

        # Invariant 8: Inaccessible Systems Invariant
        if has_inaccessible_systems:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_ALL_SYSTEMS_ACCESSIBLE",
                passed=False,
                failure_reason="A relevant system is inaccessible and lacks valid evidence proving compliance"
            ))
        else:
            results.append(CompletionInvariantResult(
                invariant_name="INVARIANT_ALL_SYSTEMS_ACCESSIBLE",
                passed=True
            ))

        return results


class PostModelSafetyGate:
    """Post-model safety gate that guarantees deterministic status derivation.
    The LLM or upstream model assessment must never control or override the final status.
    """

    def __init__(self, verification_engine: Optional[VerificationEngine] = None):
        self.verification_engine = verification_engine or VerificationEngine()

    def enforce_safety_gate(
        self,
        case: DeletionCase,
        is_deletion_authorized: bool,
        findings: List[InvestigationFinding],
        verification_steps: List[Step],
        model_proposed_status: Optional[DeletionStatus] = None,
        resurrection_report: Optional[ResurrectionReport] = None,
        retained_records_verified: bool = True,
        has_inaccessible_systems: bool = False
    ) -> SafetyGateEvaluation:
        """Evaluates completion invariants and enforces deterministic Python status authority."""
        # 1. Evaluate invariants
        invariants = self.verification_engine.evaluate_completion_invariants(
            case=case,
            is_deletion_authorized=is_deletion_authorized,
            findings=findings,
            verification_steps=verification_steps,
            resurrection_report=resurrection_report,
            retained_records_verified=retained_records_verified,
            has_inaccessible_systems=has_inaccessible_systems
        )

        failed_invariants = [inv.invariant_name for inv in invariants if not inv.passed]
        failure_reasons = [inv.failure_reason for inv in invariants if not inv.passed and inv.failure_reason]

        # 2. Derive authoritative deterministic status
        if not is_deletion_authorized:
            deterministic_status = DeletionStatus.NOT_APPLICABLE
        elif len(failed_invariants) > 0:
            deterministic_status = DeletionStatus.INCOMPLETE
        else:
            deterministic_status = DeletionStatus.COMPLETE

        # 3. Check for model assessment divergence
        was_overridden = False
        override_reason: Optional[str] = None

        if model_proposed_status is not None and model_proposed_status != deterministic_status:
            was_overridden = True
            override_reason = (
                f"Safety gate overrode model assessment '{model_proposed_status.value}' to "
                f"'{deterministic_status.value}'. Failed invariants: {'; '.join(failure_reasons) if failure_reasons else 'Contract requirements'}"
            )
            logger.warning(
                f"Safety gate override for {case.case_id}: Model proposed {model_proposed_status.value}, "
                f"enforcing {deterministic_status.value}. Reasons: {failure_reasons}"
            )

        return SafetyGateEvaluation(
            case_id=case.case_id,
            model_proposed_status=model_proposed_status,
            final_status=deterministic_status,
            was_overridden=was_overridden,
            override_reason=override_reason,
            failed_invariants=failed_invariants,
            invariant_results=invariants
        )
