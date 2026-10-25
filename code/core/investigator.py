"""Cross-system record investigation and historical event reconstruction.
Investigates residual records, prohibited identifiers, data flows, and restore risks
across evidence sources, reconstructing chronological events up to audit_at.
"""
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple, Any

from code.models import (
    IdentityEnvelope, DeletionCase, Operation, ResourceState,
    HistoricalEvent, InvestigationFinding, InvestigationReport
)
from code.core.evidence_store import EvidenceStore, EvidenceObservation
from code.core.policy_engine import PolicyEngine
from code.core.logging_utils import get_logger, mask_email

logger = get_logger("CrossSystemInvestigator")

class CrossSystemInvestigator:
    """Investigates records across evidence sources and reconstructs historical deletion workflows."""

    def __init__(
        self,
        evidence_store: EvidenceStore,
        policy_engine: PolicyEngine,
        system_activities: List[Dict[str, str]]
    ):
        self.evidence_store = evidence_store
        self.policy_engine = policy_engine
        self.system_activities = system_activities
        self._index_activities()

    def _index_activities(self) -> None:
        """Indexes global system activity by resource_id and source_system."""
        self.activities_by_resource: Dict[str, List[Dict[str, str]]] = {}
        self.deletion_worker_activities: List[Dict[str, str]] = []

        for a in self.system_activities:
            res_id = a.get("resource_id", "")
            if res_id:
                self.activities_by_resource.setdefault(res_id, []).append(a)
            if a.get("source_system") == "deletion_worker":
                self.deletion_worker_activities.append(a)

    def reconstruct_events(
        self, case: DeletionCase, target_resources: Optional[Set[str]] = None
    ) -> List[HistoricalEvent]:
        """Reconstructs historical deletion events and timeline up to audit_at."""
        events: List[HistoricalEvent] = []
        target_res = target_resources or set()

        try:
            req_dt = datetime.fromisoformat(case.requested_at.replace("Z", "+00:00"))
            rep_dt = datetime.fromisoformat(case.reported_at.replace("Z", "+00:00"))
            audit_dt = datetime.fromisoformat(case.audit_at.replace("Z", "+00:00"))
        except Exception as e:
            logger.warning(f"Failed to parse case timestamps for {case.case_id}: {e}")
            return []

        # Find workflow activities around requested/reported window
        for a in self.deletion_worker_activities:
            event_time = a.get("event_time", "")
            if not event_time:
                continue
            try:
                a_dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                # Activity must occur before audit_at cutoff
                if a_dt > audit_dt:
                    continue
                # Within window: from requested_at to reported_at + 3 hours
                if (req_dt - timedelta(hours=1)) <= a_dt <= (rep_dt + timedelta(hours=3)):
                    events.append(HistoricalEvent(
                        event_id=a.get("activity_id", ""),
                        timestamp=event_time,
                        event_type=a.get("event_type", ""),
                        source_system=a.get("source_system", ""),
                        target_system=a.get("target_system", ""),
                        resource_id=a.get("resource_id", ""),
                        reported_result=a.get("reported_result", ""),
                        is_claim=True,
                        provenance_file="system_activity.csv",
                        details={"details": a.get("details", "")}
                    ))
            except Exception:
                continue

        # Also pull activities specifically referencing target resources
        for res_id in target_res:
            for a in self.activities_by_resource.get(res_id, []):
                event_time = a.get("event_time", "")
                if not event_time:
                    continue
                try:
                    a_dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                    if a_dt <= audit_dt:
                        ev_id = a.get("activity_id", "")
                        if not any(e.event_id == ev_id for e in events):
                            events.append(HistoricalEvent(
                                event_id=ev_id,
                                timestamp=event_time,
                                event_type=a.get("event_type", ""),
                                source_system=a.get("source_system", ""),
                                target_system=a.get("target_system", ""),
                                resource_id=res_id,
                                reported_result=a.get("reported_result", ""),
                                is_claim=True,
                                provenance_file="system_activity.csv",
                                details={"details": a.get("details", "")}
                            ))
                except Exception:
                    continue

        # Sort events chronologically
        events.sort(key=lambda x: x.timestamp)
        return events

    def investigate(
        self,
        case: DeletionCase,
        envelope: IdentityEnvelope,
        target_resource_ids: Optional[Set[str]] = None
    ) -> InvestigationReport:
        """Performs cross-system record investigation, policy checking, and event reconstruction."""
        # Step 1: Reconstruct historical activity claims
        reconstructed_events = self.reconstruct_events(case, target_resource_ids)

        # Discover target resources from reconstructed events
        workflow_resources: Dict[str, Tuple[str, str, str]] = {}  # res_id -> (sys_id, action, result)
        for ev in reconstructed_events:
            if ev.resource_id:
                workflow_resources[ev.resource_id] = (ev.target_system, ev.event_type, ev.reported_result)

        all_target_res = set(workflow_resources.keys())
        if target_resource_ids:
            all_target_res.update(target_resource_ids)

        # Step 2: Query point-in-time evidence observations up to audit_at
        observations = self.evidence_store.query_subject_observations(
            identity=envelope,
            audit_at=case.audit_at,
            additional_resource_ids=all_target_res
        )

        # Keep latest observation per (system_id, resource_id)
        latest_obs_map: Dict[Tuple[str, str], EvidenceObservation] = {}
        for obs in observations:
            key = (obs.system_id, obs.resource_id)
            if key not in latest_obs_map:
                latest_obs_map[key] = obs
            elif obs.captured_at > latest_obs_map[key].captured_at:
                latest_obs_map[key] = obs
            elif obs.captured_at == latest_obs_map[key].captured_at:
                # Same timestamp tie-breaker: a non-compliant state (PRESENT/ACTIVE/has_exposed_pii) takes precedence
                curr_compliant = (
                    latest_obs_map[key].state in [ResourceState.ABSENT, ResourceState.REDACTED, ResourceState.ANONYMIZED, ResourceState.DISABLED, ResourceState.BLOCKED]
                    and not latest_obs_map[key].has_exposed_pii
                )
                new_non_compliant = (obs.state in [ResourceState.PRESENT, ResourceState.ACTIVE] or obs.has_exposed_pii)
                if curr_compliant and new_non_compliant:
                    latest_obs_map[key] = obs

        # Step 3: Evaluate records against applicable deletion policy rules
        findings: List[InvestigationFinding] = []
        evidence_gaps: List[str] = []

        # Prepare direct identifiers present in subject envelope
        subject_emails = {em.lower() for em in envelope.emails}
        subject_phones = {ph.lower() for ph in envelope.phones}
        subject_hashes = {h.lower() for h in envelope.email_hashes}

        for (sys_id, res_id), obs in latest_obs_map.items():
            # Build fields present in observation
            fields_present = dict(obs.details) if obs.details else {}
            if obs.matched_keys:
                fields_present["matched_keys"] = list(obs.matched_keys)

            # Check direct identifiers found in this record
            found_identifiers: List[str] = []
            for k in obs.matched_keys:
                if k.lower() in subject_emails:
                    found_identifiers.append(f"email:{k}")
                elif k.lower() in subject_phones:
                    found_identifiers.append(f"phone:{k}")
                elif k.lower() in subject_hashes:
                    found_identifiers.append(f"hash:{k}")

            # Check special case for ACCOUNT_TOMBSTONE:
            # Policy explicitly allows stable user_id, but forbids direct PII (name, email, phone, hash)
            is_tombstone = (obs.category == "ACCOUNT_TOMBSTONE" or sys_id == "identity_service")
            is_flow = (obs.category == "DATA_FLOW" or sys_id == "integration_service")
            is_restore = (obs.category == "BACKUP_ARCHIVE" or sys_id == "backup_service")

            # Evaluate with PolicyEngine
            evaluation = self.policy_engine.evaluate_record(
                category=obs.category,
                observed_state=obs.state,
                record_fields=fields_present,
                details={
                    "has_exposed_pii": obs.has_exposed_pii,
                    "enabled": (obs.state == ResourceState.ACTIVE) if is_flow else False,
                    "restore_allowed": (obs.state == ResourceState.ACTIVE) if is_restore else False
                }
            )

            # Check for exposed PII if flag is set on observation
            if obs.has_exposed_pii and evaluation.is_compliant:
                # If observation has exposed PII, it cannot be considered compliant
                if is_tombstone or obs.category in ["SUPPORT_MESSAGE", "ANALYTICS_PROFILE"]:
                    findings.append(InvestigationFinding(
                        system_id=sys_id,
                        resource_id=res_id,
                        operation=Operation.REPORT_EXPOSED_PII,
                        state=ResourceState.PRESENT,
                        evidence_id=obs.file_id,
                        category=obs.category,
                        observed_at=obs.captured_at,
                        source_file=obs.file_id,
                        prohibited_identifiers_found=found_identifiers,
                        is_fact=True,
                        explanation=f"Prohibited direct PII remains exposed in {obs.category} {res_id}"
                    ))
                    continue

            if not evaluation.is_compliant:
                # Non-compliant record detected by policy rule
                finding_op = evaluation.finding_operation or Operation.REPORT_REMAINING_RECORD
                findings.append(InvestigationFinding(
                    system_id=sys_id,
                    resource_id=res_id,
                    operation=finding_op,
                    state=evaluation.observed_state,
                    evidence_id=obs.file_id,
                    category=obs.category,
                    observed_at=obs.captured_at,
                    source_file=obs.file_id,
                    prohibited_identifiers_found=found_identifiers or evaluation.exposed_prohibited_fields,
                    is_fact=True,
                    explanation=evaluation.violation_reason or f"Violation of {evaluation.required_action} rule for {obs.category}"
                ))

        # Step 4: Detect evidence gaps and discrepancies between claims and evidence
        for res_id, (wf_sys, wf_action, wf_res) in workflow_resources.items():
            key = (wf_sys, res_id)
            if key not in latest_obs_map:
                evidence_gaps.append(
                    f"Workflow activity claimed {wf_action} with result '{wf_res}' on {wf_sys}:{res_id}, but no direct evidence was captured before {case.audit_at}"
                )
            else:
                obs = latest_obs_map[key]
                if wf_res == "SUCCESS" and obs.state == ResourceState.PRESENT and wf_action == "DELETE_RECORD":
                    evidence_gaps.append(
                        f"Discrepancy: Workflow claimed SUCCESS for deletion of {res_id}, but evidence {obs.file_id} confirms record is still PRESENT"
                    )

        # Distinguish observed facts from claims
        report = InvestigationReport(
            case_id=case.case_id,
            primary_user_id=envelope.user_id,
            findings=findings,
            reconstructed_events=reconstructed_events,
            evidence_gaps=evidence_gaps,
            observed_resources=latest_obs_map
        )
        return report
