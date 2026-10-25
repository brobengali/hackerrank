"""Domain data structures and enumerations for the deletion audit agent.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Dict, Any, Tuple

class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class Phase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"

class Operation(str, Enum):
    # Finding phase operations
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    
    # Remediation phase operations
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    
    # Verification phase operations
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"

class ResourceState(str, Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"

# Canonical ordering weights for sorting operations within a phase
OPERATION_ORDER: Dict[Operation, int] = {
    # Findings
    Operation.REPORT_REMAINING_RECORD: 1,
    Operation.REPORT_EXPOSED_PII: 2,
    Operation.REPORT_ACTIVE_DATA_FLOW: 3,
    Operation.REPORT_RESTORE_RISK: 4,
    
    # Remediation
    Operation.DISABLE_DATA_FLOW: 1,
    Operation.BLOCK_RESTORE: 2,
    Operation.DELETE_RECORD: 3,
    Operation.REDACT_RECORD: 4,
    Operation.ANONYMIZE_RECORD: 5,
    
    # Verification
    Operation.VERIFY_RECORD_ABSENT: 1,
    Operation.VERIFY_RECORD_PRESENT: 2,
    Operation.VERIFY_RECORD_REDACTED: 3,
    Operation.VERIFY_RECORD_ANONYMIZED: 4,
    Operation.VERIFY_DATA_FLOW_DISABLED: 5,
    Operation.VERIFY_RESTORE_BLOCKED: 6,
}

PHASE_ORDER: Dict[Phase, int] = {
    Phase.FINDING: 1,
    Phase.REMEDIATION: 2,
    Phase.VERIFICATION: 3,
}

@dataclass(frozen=True)
class SourceProvenance:
    source_file: str
    row_number: int
    entity_id: Optional[str] = None
    captured_at: Optional[str] = None

@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN
    provenance: Optional[SourceProvenance] = None

@dataclass(frozen=True)
class UserIdentityRecord:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: str
    provenance: Optional[SourceProvenance] = None

@dataclass(frozen=True)
class UserAuditLogRecord:
    audit_id: str
    user_id: str
    event_time: str
    field_name: str
    old_value: str
    new_value: str
    provenance: Optional[SourceProvenance] = None

@dataclass(frozen=True)
class SystemActivityRecord:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    provenance: Optional[SourceProvenance] = None

@dataclass(frozen=True)
class EvidenceFileRecord:
    file_id: str
    file_path: str
    origin: str
    captured_at: str
    provenance: Optional[SourceProvenance] = None

class MatchType(str, Enum):
    EXACT_CURRENT_EMAIL = "EXACT_CURRENT_EMAIL"
    EXACT_HISTORICAL_EMAIL = "EXACT_HISTORICAL_EMAIL"
    EXACT_USER_ID = "EXACT_USER_ID"
    EXACT_EMAIL_HASH = "EXACT_EMAIL_HASH"
    AMBIGUOUS_COLLISION = "AMBIGUOUS_COLLISION"
    UNRESOLVED = "UNRESOLVED"

class MatchConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    AMBIGUOUS = "AMBIGUOUS"
    UNREGISTERED = "UNREGISTERED"

@dataclass(frozen=True)
class IdentityEvidenceItem:
    source_file: str
    source_record_id: str
    field_name: str
    matched_value: str
    event_time: Optional[str]
    description: str

@dataclass(frozen=True)
class IdentityEnvelope:
    user_id: str
    canonical_name: str
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)

@dataclass(frozen=True)
class IdentityResolutionResult:
    envelope: Optional[IdentityEnvelope]
    match_type: MatchType
    confidence: MatchConfidence
    primary_user_id: Optional[str]
    evidence_trail: List[IdentityEvidenceItem] = field(default_factory=list)
    collisions: List[str] = field(default_factory=list)
    is_ambiguous: bool = False
    is_registered: bool = True


@dataclass
class DiscoveredResource:
    system_id: str
    resource_id: str
    category: str
    observed_state: ResourceState
    evidence_id: str
    captured_at: str
    has_exposed_pii: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[SourceProvenance] = None

@dataclass(frozen=True)
class Step:
    step_no: int
    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: ResourceState
    evidence_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase.value,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "state": self.state.value,
            "evidence_id": self.evidence_id,
        }

@dataclass
class DeletionCase:
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str
    provenance: Optional[SourceProvenance] = None

@dataclass
class CaseAuditResult:
    case_id: str
    status: DeletionStatus
    steps: List[Step] = field(default_factory=list)

@dataclass(frozen=True)
class OutputRow:
    case_id: str
    deletion_status: DeletionStatus
    steps_json: str

    def to_csv_dict(self) -> Dict[str, str]:
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status.value,
            "steps_json": self.steps_json
        }

class ValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

@dataclass(frozen=True)
class ValidationIssue:
    severity: ValidationSeverity
    source_file: str
    row_number: int
    field: str
    message: str
    raw_value: Optional[str] = None

@dataclass(frozen=True)
class PolicyEvaluation:
    category: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN
    is_compliant: bool
    observed_state: ResourceState
    finding_operation: Optional[Operation] = None
    remediation_operation: Optional[Operation] = None
    verification_operation: Optional[Operation] = None
    target_remediation_state: Optional[ResourceState] = None
    target_verification_state: Optional[ResourceState] = None
    violation_reason: Optional[str] = None
    exposed_prohibited_fields: List[str] = field(default_factory=list)

@dataclass(frozen=True)
class HistoricalEvent:
    event_id: str
    timestamp: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    is_claim: bool = True
    provenance_file: str = "system_activity.csv"
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class InvestigationFinding:
    system_id: str
    resource_id: str
    operation: Operation
    state: ResourceState
    evidence_id: str
    category: str
    observed_at: str
    source_file: str
    prohibited_identifiers_found: List[str] = field(default_factory=list)
    is_fact: bool = True
    explanation: str = ""

@dataclass
class InvestigationReport:
    case_id: str
    primary_user_id: Optional[str]
    findings: List[InvestigationFinding] = field(default_factory=list)
    reconstructed_events: List[HistoricalEvent] = field(default_factory=list)
    evidence_gaps: List[str] = field(default_factory=list)
    observed_resources: Dict[Tuple[str, str], Any] = field(default_factory=dict)

class ProcessStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class ResurrectionRisk:
    process_ref: str
    source_system: str
    destination_system: str
    process_type: str  # SYNC, DATA_FLOW, RESTORE, REPLICATION, IMPORT, REPLAY
    status: ProcessStatus
    can_recreate_data: bool
    evidence_id: str = ""
    source_file: str = ""
    observed_at: str = ""
    relevant_records: List[str] = field(default_factory=list)
    relevant_identifiers: List[str] = field(default_factory=list)
    existing_controls: List[str] = field(default_factory=list)
    required_remediation: Optional[Operation] = None
    target_remediation_state: Optional[ResourceState] = None
    verification_requirement: Optional[Operation] = None
    is_confirmed_active: bool = False
    explanation: str = ""

@dataclass
class ResurrectionReport:
    case_id: str
    risks: List[ResurrectionRisk] = field(default_factory=list)
    active_risks: List[ResurrectionRisk] = field(default_factory=list)
    controlled_processes: List[ResurrectionRisk] = field(default_factory=list)
    historical_processes: List[ResurrectionRisk] = field(default_factory=list)
    uncertain_processes: List[ResurrectionRisk] = field(default_factory=list)

class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"

@dataclass
class RemediationAction:
    action_id: str
    finding_id: str
    system_id: str
    resource_id: str
    operation: Operation
    target_state: ResourceState
    dependencies: List[str] = field(default_factory=list)
    status: ActionStatus = ActionStatus.PROPOSED
    is_destructive: bool = False
    is_authorized: bool = False
    expected_result: str = ""
    verification_procedure: str = ""
    verification_operation: Optional[Operation] = None

@dataclass
class RemediationPlan:
    plan_id: str
    case_id: str
    actions: List[RemediationAction] = field(default_factory=list)
    dependency_order: List[str] = field(default_factory=list)
    has_cycle: bool = False
    cycle_path: List[str] = field(default_factory=list)
    resurrection_controls_first: bool = True
    preserved_retained_records: List[str] = field(default_factory=list)

@dataclass(frozen=True)
class CompletionInvariantResult:
    invariant_name: str
    passed: bool
    failure_reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SafetyGateEvaluation:
    case_id: str
    model_proposed_status: Optional[DeletionStatus]
    final_status: DeletionStatus
    was_overridden: bool
    override_reason: Optional[str] = None
    failed_invariants: List[str] = field(default_factory=list)
    invariant_results: List[CompletionInvariantResult] = field(default_factory=list)

@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters_schema: Dict[str, Any]

@dataclass
class ToolCall:
    tool_name: str
    arguments: Dict[str, Any]
    call_id: str = ""

@dataclass
class ToolResult:
    call_id: str
    tool_name: str
    success: bool
    data: Any = None
    error: Optional[str] = None

@dataclass
class AIAssistedAuditResult:
    case_id: str
    proposed_status: Optional[DeletionStatus] = None
    rationale: str = ""
    findings: List[InvestigationFinding] = field(default_factory=list)
    proposed_actions: List[RemediationAction] = field(default_factory=list)
    tool_calls_count: int = 0
    loop_iterations: int = 0
    was_fallback: bool = False
    error: Optional[str] = None


