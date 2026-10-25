"""Resurrection detection engine.
Investigates process records, system relationships, event streams, and evidence
to identify synchronization, restore, replication, and pipeline paths capable of
recreating prohibited personal data.
"""
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple, Any

from code.models import (
    IdentityEnvelope, DeletionCase, Operation, ResourceState,
    ProcessStatus, ResurrectionRisk, ResurrectionReport, InvestigationFinding
)
from code.core.evidence_store import EvidenceStore, EvidenceObservation
from code.core.policy_engine import PolicyEngine
from code.core.logging_utils import get_logger

logger = get_logger("ResurrectionEngine")

class ResurrectionEngine:
    """Detects active and historical resurrection paths across data flows, restores, syncs, and replicas."""

    def __init__(
        self,
        evidence_store: EvidenceStore,
        policy_engine: PolicyEngine,
        system_activities: List[Dict[str, str]]
    ):
        self.evidence_store = evidence_store
        self.policy_engine = policy_engine
        self.system_activities = system_activities
        self._index_activity_streams()

    def _index_activity_streams(self) -> None:
        """Indexes resurrection-related activities by resource ID and event type."""
        self.activities_by_resource: Dict[str, List[Dict[str, str]]] = {}
        self.activities_by_type: Dict[str, List[Dict[str, str]]] = {}

        for a in self.system_activities:
            res_id = a.get("resource_id", "")
            ev_type = a.get("event_type", "")
            if res_id:
                self.activities_by_resource.setdefault(res_id, []).append(a)
            if ev_type:
                self.activities_by_type.setdefault(ev_type, []).append(a)

    def detect_resurrection_risks(
        self,
        case: DeletionCase,
        envelope: IdentityEnvelope,
        target_resource_ids: Optional[Set[str]] = None
    ) -> ResurrectionReport:
        """Investigates process records, system flows, and evidence to identify resurrection risks."""
        all_risks: List[ResurrectionRisk] = []
        active_risks: List[ResurrectionRisk] = []
        controlled_processes: List[ResurrectionRisk] = []
        historical_processes: List[ResurrectionRisk] = []
        uncertain_processes: List[ResurrectionRisk] = []

        try:
            audit_dt = datetime.fromisoformat(case.audit_at.replace("Z", "+00:00"))
            req_dt = datetime.fromisoformat(case.requested_at.replace("Z", "+00:00"))
        except Exception as e:
            logger.warning(f"Failed to parse case timestamps for {case.case_id}: {e}")
            audit_dt = datetime.max

        target_res = target_resource_ids or set()

        # Step 1: Query point-in-time evidence observations for process states
        obs_list = self.evidence_store.query_subject_observations(
            identity=envelope,
            audit_at=case.audit_at,
            additional_resource_ids=target_res
        )

        # Map latest observation per (system_id, resource_id)
        latest_obs: Dict[Tuple[str, str], EvidenceObservation] = {}
        for obs in obs_list:
            key = (obs.system_id, obs.resource_id)
            if key not in latest_obs or obs.captured_at > latest_obs[key].captured_at:
                latest_obs[key] = obs

        # Step 2: Investigate Data Flows (integration_service / DATA_FLOW)
        for (sys_id, res_id), obs in latest_obs.items():
            if obs.category == "DATA_FLOW" or sys_id == "integration_service":
                is_active = (obs.state == ResourceState.ACTIVE)
                status = ProcessStatus.ACTIVE if is_active else ProcessStatus.INACTIVE
                risk = ResurrectionRisk(
                    process_ref=res_id,
                    source_system="integration_service",
                    destination_system="downstream_stores",
                    process_type="DATA_FLOW",
                    status=status,
                    can_recreate_data=is_active,
                    evidence_id=obs.file_id,
                    source_file=obs.file_id,
                    observed_at=obs.captured_at,
                    relevant_records=[res_id],
                    relevant_identifiers=list(obs.matched_keys),
                    existing_controls=[] if is_active else ["Data flow disabled in connector configuration"],
                    required_remediation=Operation.DISABLE_DATA_FLOW if is_active else None,
                    target_remediation_state=ResourceState.DISABLED if is_active else None,
                    verification_requirement=Operation.VERIFY_DATA_FLOW_DISABLED,
                    is_confirmed_active=is_active,
                    explanation=(
                        f"Active integration connector {res_id} can recreate downstream subject data"
                        if is_active else f"Integration connector {res_id} is disabled"
                    )
                )
                all_risks.append(risk)
                if is_active:
                    active_risks.append(risk)
                else:
                    controlled_processes.append(risk)

        # Step 3: Investigate Backup Restore Risks (backup_service / BACKUP_ARCHIVE)
        for (sys_id, res_id), obs in latest_obs.items():
            if obs.category == "BACKUP_ARCHIVE" or sys_id == "backup_service":
                is_active = (obs.state == ResourceState.ACTIVE)
                status = ProcessStatus.ACTIVE if is_active else ProcessStatus.INACTIVE
                risk = ResurrectionRisk(
                    process_ref=res_id,
                    source_system="backup_service",
                    destination_system="primary_databases",
                    process_type="RESTORE",
                    status=status,
                    can_recreate_data=is_active,
                    evidence_id=obs.file_id,
                    source_file=obs.file_id,
                    observed_at=obs.captured_at,
                    relevant_records=[res_id],
                    relevant_identifiers=list(obs.matched_keys),
                    existing_controls=[] if is_active else ["Restore access blocked for archive"],
                    required_remediation=Operation.BLOCK_RESTORE if is_active else None,
                    target_remediation_state=ResourceState.BLOCKED if is_active else None,
                    verification_requirement=Operation.VERIFY_RESTORE_BLOCKED,
                    is_confirmed_active=is_active,
                    explanation=(
                        f"Backup archive {res_id} can restore deleted subject data"
                        if is_active else f"Restore access blocked for backup archive {res_id}"
                    )
                )
                all_risks.append(risk)
                if is_active:
                    active_risks.append(risk)
                else:
                    controlled_processes.append(risk)

        # Step 4: Investigate Activity Stream for Syncs, Replays, and Discrepancies
        for res_id in target_res:
            for act in self.activities_by_resource.get(res_id, []):
                act_time = act.get("event_time", "")
                if not act_time:
                    continue
                try:
                    a_dt = datetime.fromisoformat(act_time.replace("Z", "+00:00"))
                    if a_dt > audit_dt:
                        continue
                except Exception:
                    continue

                ev_type = act.get("event_type", "")
                src = act.get("source_system", "")
                tgt = act.get("target_system", "")
                details = act.get("details", "")

                # Historical synchronization events
                if ev_type == "SYNC_RECORD":
                    is_post_request = (a_dt >= req_dt)
                    status = ProcessStatus.HISTORICAL if not is_post_request else ProcessStatus.ACTIVE
                    risk = ResurrectionRisk(
                        process_ref=f"sync_{act.get('activity_id', res_id)}",
                        source_system=src,
                        destination_system=tgt,
                        process_type="SYNC",
                        status=status,
                        can_recreate_data=is_post_request,
                        evidence_id="",
                        source_file="system_activity.csv",
                        observed_at=act_time,
                        relevant_records=[res_id],
                        relevant_identifiers=[envelope.user_id],
                        existing_controls=["Batch sync job completed"] if not is_post_request else [],
                        is_confirmed_active=is_post_request,
                        explanation=f"Sync record activity: {details}"
                    )
                    all_risks.append(risk)
                    if is_post_request:
                        active_risks.append(risk)
                    else:
                        historical_processes.append(risk)

                # Check for unverified / missing process evidence (e.g. CHECK_DATA_FLOW claiming enabled)
                elif ev_type in ["CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"]:
                    key = (tgt, res_id)
                    if key not in latest_obs:
                        # Claimed active process without evidence corroboration before audit_at
                        risk = ResurrectionRisk(
                            process_ref=res_id,
                            source_system=src,
                            destination_system=tgt,
                            process_type="DATA_FLOW" if ev_type == "CHECK_DATA_FLOW" else "RESTORE",
                            status=ProcessStatus.UNKNOWN,
                            can_recreate_data=True,  # unverified active suspicion
                            evidence_id="",
                            source_file="system_activity.csv",
                            observed_at=act_time,
                            relevant_records=[res_id],
                            relevant_identifiers=[envelope.user_id],
                            existing_controls=[],
                            required_remediation=(
                                Operation.DISABLE_DATA_FLOW if ev_type == "CHECK_DATA_FLOW" else Operation.BLOCK_RESTORE
                            ),
                            verification_requirement=(
                                Operation.VERIFY_DATA_FLOW_DISABLED if ev_type == "CHECK_DATA_FLOW" else Operation.VERIFY_RESTORE_BLOCKED
                            ),
                            is_confirmed_active=False,
                            explanation=f"Unverified process state: activity claims {ev_type} but no corroborating evidence captured before audit_at"
                        )
                        all_risks.append(risk)
                        uncertain_processes.append(risk)

        return ResurrectionReport(
            case_id=case.case_id,
            risks=all_risks,
            active_risks=active_risks,
            controlled_processes=controlled_processes,
            historical_processes=historical_processes,
            uncertain_processes=uncertain_processes
        )

    def to_investigation_findings(self, report: ResurrectionReport) -> List[InvestigationFinding]:
        """Converts confirmed active and uncertain resurrection risks to structured InvestigationFindings."""
        findings: List[InvestigationFinding] = []
        for risk in report.active_risks + report.uncertain_processes:
            if not risk.evidence_id:
                # Do not emit step findings without participant-visible evidence ID per contract
                continue

            if risk.process_type == "DATA_FLOW":
                findings.append(InvestigationFinding(
                    system_id=risk.source_system,
                    resource_id=risk.process_ref,
                    operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                    state=ResourceState.ACTIVE,
                    evidence_id=risk.evidence_id,
                    category="DATA_FLOW",
                    observed_at=risk.observed_at,
                    source_file=risk.source_file,
                    prohibited_identifiers_found=risk.relevant_identifiers,
                    is_fact=True,
                    explanation=risk.explanation
                ))
            elif risk.process_type == "RESTORE":
                findings.append(InvestigationFinding(
                    system_id=risk.source_system,
                    resource_id=risk.process_ref,
                    operation=Operation.REPORT_RESTORE_RISK,
                    state=ResourceState.ACTIVE,
                    evidence_id=risk.evidence_id,
                    category="BACKUP_ARCHIVE",
                    observed_at=risk.observed_at,
                    source_file=risk.source_file,
                    prohibited_identifiers_found=risk.relevant_identifiers,
                    is_fact=True,
                    explanation=risk.explanation
                ))
        return findings
