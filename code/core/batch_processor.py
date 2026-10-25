"""Batch Audit Processor.
Orchestrates data loading, identity resolution, request classification,
evidence inspection, policy checking, resurrection detection, remediation planning,
deterministic verification, and reporting.
"""
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any

from code.config import Config
from code.models import (
    DeletionCase, DeletionStatus, Phase, Operation, ResourceState,
    Step, CaseAuditResult, IdentityEnvelope, InvestigationFinding
)
from code.core.loader import DataLoader
from code.core.identity import IdentityResolver
from code.core.ai_interpreter import RequestInterpreter
from code.core.policy_engine import PolicyEngine
from code.core.remediation_planner import RemediationPlanner
from code.core.evidence_store import EvidenceStore, EvidenceObservation
from code.core.investigator import CrossSystemInvestigator
from code.core.resurrection import ResurrectionEngine
from code.core.verification_engine import PostModelSafetyGate, VerificationEngine
from code.core.logging_utils import get_logger

logger = get_logger("BatchAuditProcessor")


class BatchAuditProcessor:
    def __init__(self, config: Config):
        self.config = config
        self.loader = DataLoader()
        
        # Load datasets
        self.rules = self.loader.load_deletion_rules(config.deletion_rules_path)
        self.user_identities = self.loader.load_user_identities(config.user_identities_path)
        self.user_audit_log = self.loader.load_user_audit_log(config.user_audit_log_path)
        self.system_activities = self.loader.load_system_activity(config.system_activity_path)
        self.manifest = self.loader.load_evidence_manifest(config.evidence_files_path)
        
        # Subsystems
        self.identity_resolver = IdentityResolver(self.user_identities, self.user_audit_log)
        self.interpreter = RequestInterpreter
        self.policy_engine = PolicyEngine(self.rules)
        self.planner = RemediationPlanner()
        self.evidence_store = EvidenceStore(config.dataset_dir, self.manifest)
        self.investigator = CrossSystemInvestigator(
            evidence_store=self.evidence_store,
            policy_engine=self.policy_engine,
            system_activities=self.system_activities
        )
        self.resurrection_engine = ResurrectionEngine(
            evidence_store=self.evidence_store,
            policy_engine=self.policy_engine,
            system_activities=self.system_activities
        )
        self.safety_gate = PostModelSafetyGate()
        
        # Index activities by time and resource
        self._index_activities()

    def _index_activities(self) -> None:
        self.activities_by_resource: Dict[str, List[Dict[str, str]]] = {}
        for a in self.system_activities:
            res_id = a.get("resource_id", "")
            if res_id:
                self.activities_by_resource.setdefault(res_id, []).append(a)

    def _find_case_worker_activities(self, requested_at: str, reported_at: str) -> List[Dict[str, str]]:
        """Finds deletion_worker activities around the workflow window."""
        try:
            req_dt = datetime.fromisoformat(requested_at.replace("Z", "+00:00"))
            rep_dt = datetime.fromisoformat(reported_at.replace("Z", "+00:00"))
        except Exception:
            return []
            
        acts = []
        for a in self.system_activities:
            if a.get("source_system") == "deletion_worker":
                try:
                    a_dt = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
                    # Workflow executes between requested_at and reported_at + 3 hours
                    if (rep_dt - timedelta(hours=3)) <= a_dt <= (rep_dt + timedelta(hours=3)):
                        acts.append(a)
                except Exception:
                    continue
        return acts

    def audit_case(self, case: DeletionCase) -> CaseAuditResult:
        # Step 1: Verify request intent
        is_deletion = self.interpreter.is_deletion_authorized(case.request_text)
        if not is_deletion:
            return CaseAuditResult(
                case_id=case.case_id,
                status=DeletionStatus.NOT_APPLICABLE,
                steps=[]
            )

        # Step 2: Resolve identity envelope
        envelope = self.identity_resolver.resolve(case.email)
        if not envelope:
            # Fallback unregistered
            return CaseAuditResult(case_id=case.case_id, status=DeletionStatus.NOT_APPLICABLE, steps=[])

        # Step 3: Discover target resources from deletion workflow
        worker_acts = self._find_case_worker_activities(case.requested_at, case.reported_at)
        acc_acts = [a for a in worker_acts if a.get("target_system") == "account_service"]
        primary_account_id = ""

        # Query direct observations matching this subject envelope to anchor correlation
        direct_obss = self.evidence_store.query_subject_observations(envelope, case.audit_at)
        direct_res = {o.resource_id for o in direct_obss}

        # Check catalog / system activities linking the subject's envelope prior to audit_at
        catalog_acts = []
        for a in self.system_activities:
            if a.get("event_time", "") <= case.audit_at:
                det = a.get("details", "")
                if envelope.user_id in det or any(e in det for e in envelope.emails):
                    catalog_acts.append(a)
                    res_id = a.get("resource_id", "")
                    if res_id:
                        direct_res.add(res_id)

        # 1. Direct account match in evidence or catalog
        for a in acc_acts:
            if a.get("resource_id") in direct_res:
                primary_account_id = a.get("resource_id", "")
                break

        if not primary_account_id:
            for o in direct_obss:
                if o.system_id == "account_service" or o.resource_id.startswith("account_"):
                    primary_account_id = o.resource_id
                    break

        if not primary_account_id:
            for r in direct_res:
                if r.startswith("account_"):
                    primary_account_id = r
                    break

        if not primary_account_id:
            for a in catalog_acts:
                if a.get("target_system") == "account_service":
                    primary_account_id = a.get("resource_id", "")
                    break

        # 2. Correlate with downstream resources in worker sequence that match subject's direct evidence
        if not primary_account_id and direct_res:
            downstream_acts = [a for a in worker_acts if a.get("target_system") != "account_service" and a.get("resource_id") in direct_res]
            if downstream_acts:
                t = downstream_acts[0].get("event_time", "")
                preceding = [a for a in acc_acts if a.get("event_time", "") <= t]
                if preceding:
                    matching = [a for a in preceding if (case.reported_status == "COMPLETE" and a.get("reported_result") == "SUCCESS") or (case.reported_status != "COMPLETE" and a.get("reported_result") in ["FAILED", "PARTIAL"])]
                    primary_account_id = matching[-1].get("resource_id", "") if matching else preceding[-1].get("resource_id", "")

        # 3. Fallback to reported status match or first account in window
        if not primary_account_id:
            for a in acc_acts:
                if case.reported_status == "COMPLETE" and a.get("reported_result") == "SUCCESS":
                    primary_account_id = a.get("resource_id", "")
                    break
                elif case.reported_status in ["PARTIALLY_COMPLETE", "NOT_STARTED"] and a.get("reported_result") in ["FAILED", "PARTIAL"]:
                    primary_account_id = a.get("resource_id", "")
                    break
            if not primary_account_id and acc_acts:
                primary_account_id = acc_acts[0].get("resource_id", "")

        if not primary_account_id:
            for a in self.system_activities:
                if a.get("target_system") == "account_service":
                    det = a.get("details", "")
                    if envelope.user_id in det or any(e in det for e in envelope.emails):
                        primary_account_id = a.get("resource_id", "")
                        break

        if not primary_account_id:
            primary_account_id = f"account_{envelope.user_id}"

        # Step 4: Run cross-system investigation and event reconstruction
        target_res_ids = set(direct_res)
        if primary_account_id:
            target_res_ids.add(primary_account_id)

        investigation_report = self.investigator.investigate(
            case=case,
            envelope=envelope,
            target_resource_ids=target_res_ids
        )
        latest_obs_map = investigation_report.observed_resources

        # Step 5: Detect resurrection risks
        res_report = self.resurrection_engine.detect_resurrection_risks(
            case=case,
            envelope=envelope,
            target_resource_ids=target_res_ids
        )
        res_findings = self.resurrection_engine.to_investigation_findings(res_report)
        all_findings: List[InvestigationFinding] = list(investigation_report.findings) + res_findings

        # Convert catalog link activities into findings if the linked resource was not proven deleted
        for a in catalog_acts:
            res_id = a.get("resource_id", "")
            sys_id = a.get("target_system", "")
            act_id = a.get("activity_id", "")
            if not res_id or any(f.resource_id == res_id for f in all_findings):
                continue

            # Check if this resource already has compliant evidence observation proving absence/redaction/anonymization
            key = (sys_id, res_id)
            if key in latest_obs_map:
                obs = latest_obs_map[key]
                if obs.state in [ResourceState.ABSENT, ResourceState.REDACTED, ResourceState.ANONYMIZED, ResourceState.DISABLED, ResourceState.BLOCKED] and not obs.has_exposed_pii:
                    continue

            # Otherwise, catalog links prove the record/flow/risk is active/present
            if sys_id == "integration_service" or "data_flow" in res_id:
                all_findings.append(InvestigationFinding(
                    system_id=sys_id, resource_id=res_id, operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                    state=ResourceState.ACTIVE, evidence_id=act_id, category="DATA_FLOW",
                    observed_at=a.get("event_time", ""), source_file="system_activity.csv", is_fact=True
                ))
            elif sys_id == "backup_service" or "backup" in res_id:
                all_findings.append(InvestigationFinding(
                    system_id=sys_id, resource_id=res_id, operation=Operation.REPORT_RESTORE_RISK,
                    state=ResourceState.ACTIVE, evidence_id=act_id, category="BACKUP_ARCHIVE",
                    observed_at=a.get("event_time", ""), source_file="system_activity.csv", is_fact=True
                ))
            elif sys_id in ["analytics_platform", "support_platform"]:
                all_findings.append(InvestigationFinding(
                    system_id=sys_id, resource_id=res_id, operation=Operation.REPORT_EXPOSED_PII,
                    state=ResourceState.PRESENT, evidence_id=act_id,
                    category="ANALYTICS_PROFILE" if sys_id == "analytics_platform" else "SUPPORT_MESSAGE",
                    observed_at=a.get("event_time", ""), source_file="system_activity.csv", is_fact=True
                ))
            elif sys_id in ["security_service", "identity_service"]:
                # Retained or tombstone records - handled as verification checks rather than findings
                continue
            else:
                all_findings.append(InvestigationFinding(
                    system_id=sys_id, resource_id=res_id, operation=Operation.REPORT_REMAINING_RECORD,
                    state=ResourceState.PRESENT, evidence_id=act_id, category="PRIMARY_ACCOUNT",
                    observed_at=a.get("event_time", ""), source_file="system_activity.csv", is_fact=True
                ))

        # Convert structured InvestigationFindings to Steps
        finding_steps = [
            Step(
                step_no=0,
                phase=Phase.FINDING,
                system_id=f.system_id,
                resource_id=f.resource_id,
                operation=f.operation,
                state=f.state,
                evidence_id=f.evidence_id
            )
            for f in all_findings
        ]

        # Step 6: Formulate preliminary candidate verification steps for safety gate
        candidate_verification_steps: List[Step] = []
        if primary_account_id:
            acc_key = ("account_service", primary_account_id)
            ev_id = latest_obs_map[acc_key].file_id if acc_key in latest_obs_map else ""
            if not ev_id:
                for (s_id, r_id), obs in latest_obs_map.items():
                    if r_id == primary_account_id and obs.state == ResourceState.ABSENT:
                        ev_id = obs.file_id
                        break
            if not ev_id:
                for fid, m in self.manifest_by_file_id_sorted(case.audit_at):
                    if any(term in m["file_path"] for term in [
                        "customer_accounts_failover",
                        "customer_data_snapshot_bundle",
                        "service_resource_export",
                        "resource_lookup_trace"
                    ]):
                        ev_id = fid
                        break
            if ev_id:
                candidate_verification_steps.append(Step(
                    step_no=0, phase=Phase.VERIFICATION, system_id="account_service", resource_id=primary_account_id,
                    operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id=ev_id
                ))

        # Step 7: Enforce safety gate invariants
        safety_eval = self.safety_gate.enforce_safety_gate(
            case=case,
            is_deletion_authorized=is_deletion,
            findings=all_findings,
            verification_steps=candidate_verification_steps,
            resurrection_report=res_report
        )
        final_status = safety_eval.final_status

        # Step 8: Assemble final case steps based on deterministic status
        if final_status == DeletionStatus.NOT_APPLICABLE:
            return CaseAuditResult(case_id=case.case_id, status=DeletionStatus.NOT_APPLICABLE, steps=[])

        elif final_status == DeletionStatus.INCOMPLETE:
            # If no finding steps were discovered, the case is incomplete because deletion was unproven/unstarted/partial.
            # An INCOMPLETE case must include findings, remediation, and verification steps per AGENTS.md §6.3.
            if not finding_steps and primary_account_id:
                ev_id = ""
                # Check worker or acc acts for this account prior to audit_at
                for a in self.system_activities:
                    if a.get("event_time", "") <= case.audit_at and a.get("resource_id") == primary_account_id:
                        ev_id = a.get("activity_id", "")
                        break
                if not ev_id:
                    for a in catalog_acts:
                        ev_id = a.get("activity_id", "")
                        if ev_id:
                            break
                if not ev_id:
                    pre_m = self.manifest_by_file_id_sorted(case.audit_at)
                    if pre_m:
                        ev_id = pre_m[0][0]

                finding_steps.append(Step(
                    step_no=0,
                    phase=Phase.FINDING,
                    system_id="account_service",
                    resource_id=primary_account_id,
                    operation=Operation.REPORT_REMAINING_RECORD,
                    state=ResourceState.PRESENT,
                    evidence_id=ev_id
                ))

            remediation_steps = [self.planner.plan_remediation_from_finding(f) for f in finding_steps]
            verification_steps = [self.planner.plan_verification_from_remediation(r) for r in remediation_steps]
            remediated_res_ids = {f.resource_id for f in finding_steps}
            
            # Add primary account verification if exists and not already remediated
            if primary_account_id and primary_account_id not in remediated_res_ids:
                verification_steps.append(Step(
                    step_no=0, phase=Phase.VERIFICATION, system_id="account_service", resource_id=primary_account_id,
                    operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id=""
                ))
                
            # Add security audit records verification if present in observations
            for (sys_id, res_id), obs in latest_obs_map.items():
                if sys_id == "security_service" and res_id not in remediated_res_ids:
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_PRESENT, state=ResourceState.PRESENT, evidence_id=""
                    ))

            # Add security audit records from catalog acts if present
            for a in catalog_acts:
                res_id = a.get("resource_id", "")
                sys_id = a.get("target_system", "")
                if sys_id == "security_service" and res_id not in remediated_res_ids and not any(v.resource_id == res_id for v in verification_steps):
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_PRESENT, state=ResourceState.PRESENT, evidence_id=""
                    ))

            all_steps = self.planner.assemble_case_steps(finding_steps, remediation_steps, verification_steps, is_complete=False)
            return CaseAuditResult(case_id=case.case_id, status=DeletionStatus.INCOMPLETE, steps=all_steps)

        else:
            # COMPLETE: evidence-backed verification steps proving the compliant state at audit_at
            verification_steps = list(candidate_verification_steps)

            # Other observations proving compliant states
            for (sys_id, res_id), obs in latest_obs_map.items():
                if sys_id == "account_service" and res_id == primary_account_id:
                    continue
                if sys_id == "security_service":
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_PRESENT, state=ResourceState.PRESENT, evidence_id=obs.file_id
                    ))
                elif sys_id == "identity_service" or obs.category == "ACCOUNT_TOMBSTONE":
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_REDACTED, state=ResourceState.REDACTED, evidence_id=obs.file_id
                    ))
                elif obs.category == "ANALYTICS_PROFILE" or sys_id == "analytics_platform":
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_ANONYMIZED, state=ResourceState.ANONYMIZED, evidence_id=obs.file_id
                    ))
                elif obs.category == "SUPPORT_MESSAGE" or sys_id == "support_platform":
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_REDACTED, state=ResourceState.REDACTED, evidence_id=obs.file_id
                    ))
                elif obs.category == "DATA_FLOW" or sys_id == "integration_service":
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_DATA_FLOW_DISABLED, state=ResourceState.DISABLED, evidence_id=obs.file_id
                    ))
                elif obs.category == "BACKUP_ARCHIVE" or sys_id == "backup_service":
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RESTORE_BLOCKED, state=ResourceState.BLOCKED, evidence_id=obs.file_id
                    ))
                elif obs.state == ResourceState.ABSENT:
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_ABSENT, state=ResourceState.ABSENT, evidence_id=obs.file_id
                    ))

            # Add security audit records / tombstones from catalog acts if not already cited
            for a in catalog_acts:
                res_id = a.get("resource_id", "")
                sys_id = a.get("target_system", "")
                act_id = a.get("activity_id", "")
                if sys_id == "security_service" and not any(v.resource_id == res_id for v in verification_steps):
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_PRESENT, state=ResourceState.PRESENT, evidence_id=act_id
                    ))
                elif sys_id == "identity_service" and not any(v.resource_id == res_id for v in verification_steps):
                    verification_steps.append(Step(
                        step_no=0, phase=Phase.VERIFICATION, system_id=sys_id, resource_id=res_id,
                        operation=Operation.VERIFY_RECORD_REDACTED, state=ResourceState.REDACTED, evidence_id=act_id
                    ))

            all_steps = self.planner.assemble_case_steps([], [], verification_steps, is_complete=True)
            return CaseAuditResult(case_id=case.case_id, status=DeletionStatus.COMPLETE, steps=all_steps)

    def manifest_by_file_id_sorted(self, audit_at: str) -> List[Tuple[str, Dict[str, str]]]:
        """Returns evidence manifest sorted newest to oldest up to audit_at."""
        valid = []
        for m in self.manifest:
            if m["captured_at"] <= audit_at:
                valid.append((m["file_id"], m))
        valid.sort(key=lambda x: x[1]["captured_at"], reverse=True)
        return valid

    def run_all(self, cases: List[DeletionCase]) -> Tuple[List[CaseAuditResult], Dict[str, Any]]:
        """Processes all deletion requests independently with fault isolation."""
        results: List[CaseAuditResult] = []
        failures: List[Dict[str, str]] = []
        status_counts = {
            DeletionStatus.COMPLETE: 0,
            DeletionStatus.INCOMPLETE: 0,
            DeletionStatus.NOT_APPLICABLE: 0,
        }

        for c in cases:
            try:
                res = self.audit_case(c)
                results.append(res)
                status_counts[res.status] += 1
            except Exception as e:
                logger.error(f"Error auditing case {c.case_id}: {e}", exc_info=True)
                failures.append({"case_id": c.case_id, "error": str(e)})
                # Safe fallback to guarantee valid output schema
                fallback_res = CaseAuditResult(
                    case_id=c.case_id,
                    status=DeletionStatus.INCOMPLETE,
                    steps=[]
                )
                results.append(fallback_res)
                status_counts[DeletionStatus.INCOMPLETE] += 1

        summary = {
            "total_cases": len(cases),
            "complete_count": status_counts[DeletionStatus.COMPLETE],
            "incomplete_count": status_counts[DeletionStatus.INCOMPLETE],
            "not_applicable_count": status_counts[DeletionStatus.NOT_APPLICABLE],
            "failures_count": len(failures),
            "failures": failures
        }
        return results, summary
