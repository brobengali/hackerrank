"""Deterministic deletion policy engine module.
Loads deletion_rules.csv dynamically at runtime and determines required
remediation and verification actions strictly from policy rules.
"""
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Any

from code.models import (
    DeletionRule, Operation, ResourceState, PolicyEvaluation
)
from code.core.loader import DataLoader
from code.core.errors import (
    UnknownPolicyCategoryError, ContradictoryPolicyError, InvalidDataFormatError
)

# Canonical prohibited direct identifiers across redaction categories
PROHIBITED_DIRECT_PII: Set[str] = {
    "name", "full_name", "display_name", "first_name", "last_name",
    "email", "phone", "email_hash",
    "requester_email", "requester_phone", "requester_name",
    "owner_email", "owner_phone"
}

# Fields that make an analytics or telemetry record attributable to a user
ATTRIBUTABLE_FIELDS: Set[str] = {
    "user_id", "customer_reference", "subject_reference", "correlation_key",
    "email", "phone", "email_hash", "name"
}

# Stable identifiers permitted on retained account tombstones
TOMBSTONE_PERMITTED_FIELDS: Set[str] = {
    "user_id", "subject_reference", "customer_reference",
    "resource_id", "account_status", "status", "updated_at", "created_at"
}


class PolicyEngine:
    """Deterministic policy engine enforcing runtime-loaded deletion rules."""

    def __init__(self, rules: List[DeletionRule]):
        self.rules_by_category: Dict[str, DeletionRule] = {}
        self._load_and_validate_rules(rules)

    @classmethod
    def from_file(cls, rules_path: Path) -> "PolicyEngine":
        """Parses and instantiates the policy engine directly from a deletion_rules CSV."""
        rules = DataLoader.load_deletion_rules(rules_path)
        return cls(rules)

    def _load_and_validate_rules(self, rules: List[DeletionRule]) -> None:
        """Validates rule consistency and detects contradictory rules."""
        if not rules:
            raise InvalidDataFormatError("Policy engine initialized with empty rule list")

        for r in rules:
            cat = r.data_category.strip().upper()
            action = r.required_action.strip().upper()

            if cat in self.rules_by_category:
                existing = self.rules_by_category[cat]
                if existing.required_action != action:
                    raise ContradictoryPolicyError(
                        f"Contradictory policy detected for category '{cat}': "
                        f"Rule '{existing.rule_id}' specifies '{existing.required_action}', "
                        f"while rule '{r.rule_id}' specifies '{action}'",
                        {"category": cat, "rule_1": existing.rule_id, "rule_2": r.rule_id}
                    )
            self.rules_by_category[cat] = r

    def get_rule(self, category: str) -> DeletionRule:
        """Retrieves the deletion rule for a given category.
        Rejects unknown categories rather than silently guessing defaults.
        """
        cat_upper = category.strip().upper()
        if cat_upper not in self.rules_by_category:
            raise UnknownPolicyCategoryError(
                f"No deletion rule defined for category '{category}'",
                {"category": category, "defined_categories": list(self.rules_by_category.keys())}
            )
        return self.rules_by_category[cat_upper]

    def get_action_for_category(self, category: str) -> str:
        """Returns the required action ('DELETE', 'REDACT', 'ANONYMIZE', 'RETAIN') for a category."""
        return self.get_rule(category).required_action

    @staticmethod
    def _is_non_empty(val: Any) -> bool:
        """Checks if a field value contains actual data."""
        if val is None:
            return False
        if isinstance(val, str):
            clean = val.strip().lower()
            return clean != "" and clean != "null" and clean != "none"
        return True

    def inspect_prohibited_identifiers(
        self,
        category: str,
        record_fields: Optional[Dict[str, Any]]
    ) -> Tuple[bool, List[str]]:
        """Inspects whether record fields contain prohibited identifiers according to policy.
        Returns (has_prohibited_identifiers, list_of_exposed_fields).
        """
        if not record_fields:
            return False, []

        cat_upper = category.strip().upper()
        exposed: List[str] = []

        if cat_upper == "ACCOUNT_TOMBSTONE":
            # Rule 15: Tombstone must preserve stable user_id reference,
            # but prohibited direct identifiers (name, email, phone, email_hash) must be removed.
            for k, v in record_fields.items():
                k_clean = k.strip().lower()
                if k_clean in PROHIBITED_DIRECT_PII and self._is_non_empty(v):
                    exposed.append(k)

        elif cat_upper in ["ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"]:
            # Rules 07, 08: Record must not be attributable to a user
            for k, v in record_fields.items():
                k_clean = k.strip().lower()
                if k_clean in ATTRIBUTABLE_FIELDS and self._is_non_empty(v):
                    exposed.append(k)

        elif cat_upper in ["SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"]:
            # Rules 05, 11: Retained context permitted, user contact details prohibited
            for k, v in record_fields.items():
                k_clean = k.strip().lower()
                if k_clean in PROHIBITED_DIRECT_PII and self._is_non_empty(v):
                    exposed.append(k)

        else:
            # General direct PII check
            for k, v in record_fields.items():
                k_clean = k.strip().lower()
                if k_clean in PROHIBITED_DIRECT_PII and self._is_non_empty(v):
                    exposed.append(k)

        return len(exposed) > 0, exposed

    def evaluate_record(
        self,
        category: str,
        observed_state: ResourceState,
        record_fields: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> PolicyEvaluation:
        """Deterministically evaluates a record against runtime policy rules.
        Distinguishes compliant retained records from records violating retention rules.
        """
        details = details or {}
        cat_upper = category.strip().upper()

        # Handle active data flow processes (special category from system architecture)
        if cat_upper in ["DATA_FLOW", "INTEGRATION_SERVICE"]:
            if observed_state == ResourceState.ACTIVE or details.get("enabled", False) is True:
                return PolicyEvaluation(
                    category=category,
                    required_action="DISABLE",
                    is_compliant=False,
                    observed_state=ResourceState.ACTIVE,
                    finding_operation=Operation.REPORT_ACTIVE_DATA_FLOW,
                    remediation_operation=Operation.DISABLE_DATA_FLOW,
                    verification_operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                    target_remediation_state=ResourceState.DISABLED,
                    target_verification_state=ResourceState.DISABLED,
                    violation_reason="Active data flow process can recreate or sync deleted subject data"
                )
            else:
                return PolicyEvaluation(
                    category=category,
                    required_action="DISABLE",
                    is_compliant=True,
                    observed_state=ResourceState.DISABLED,
                    verification_operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                    target_verification_state=ResourceState.DISABLED
                )

        # Standard deletion rules lookup
        rule = self.get_rule(category)
        action = rule.required_action

        has_prohibited_pii, exposed_fields = self.inspect_prohibited_identifiers(category, record_fields)

        # Explicit details override for PII presence (e.g. from structured log flags)
        if details.get("has_exposed_pii"):
            has_prohibited_pii = True
            if not exposed_fields:
                exposed_fields = ["exposed_pii_flagged"]

        # =====================================================================
        # 1. Action: DELETE (Rule 01, 02, 03, 04, 06, 09, 10)
        # =====================================================================
        if action == "DELETE":
            if observed_state == ResourceState.PRESENT:
                return PolicyEvaluation(
                    category=category,
                    required_action=action,
                    is_compliant=False,
                    observed_state=observed_state,
                    finding_operation=Operation.REPORT_REMAINING_RECORD,
                    remediation_operation=Operation.DELETE_RECORD,
                    verification_operation=Operation.VERIFY_RECORD_ABSENT,
                    target_remediation_state=ResourceState.ABSENT,
                    target_verification_state=ResourceState.ABSENT,
                    violation_reason=f"Policy requires complete deletion of {category}, but record remains PRESENT",
                    exposed_prohibited_fields=exposed_fields
                )
            else:
                return PolicyEvaluation(
                    category=category,
                    required_action=action,
                    is_compliant=True,
                    observed_state=ResourceState.ABSENT,
                    verification_operation=Operation.VERIFY_RECORD_ABSENT,
                    target_verification_state=ResourceState.ABSENT
                )

        # =====================================================================
        # 2. Action: REDACT (Rule 05, 11, 15)
        # =====================================================================
        elif action == "REDACT":
            if cat_upper == "ACCOUNT_TOMBSTONE":
                # Account tombstones are preserved records:
                # Compliant if stable internal reference remains AND prohibited direct PII is absent.
                if has_prohibited_pii:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=False,
                        observed_state=ResourceState.PRESENT,
                        finding_operation=Operation.REPORT_EXPOSED_PII,
                        remediation_operation=Operation.REDACT_RECORD,
                        verification_operation=Operation.VERIFY_RECORD_REDACTED,
                        target_remediation_state=ResourceState.REDACTED,
                        target_verification_state=ResourceState.REDACTED,
                        violation_reason=f"Account tombstone exposes prohibited direct identifiers: {exposed_fields}",
                        exposed_prohibited_fields=exposed_fields
                    )
                else:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=True,
                        observed_state=ResourceState.REDACTED,
                        verification_operation=Operation.VERIFY_RECORD_REDACTED,
                        target_verification_state=ResourceState.REDACTED
                    )

            else:
                # Other redaction categories (SUPPORT_MESSAGE, EMAIL_DELIVERY_LOG)
                if has_prohibited_pii or observed_state == ResourceState.PRESENT:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=False,
                        observed_state=ResourceState.PRESENT,
                        finding_operation=Operation.REPORT_EXPOSED_PII,
                        remediation_operation=Operation.REDACT_RECORD,
                        verification_operation=Operation.VERIFY_RECORD_REDACTED,
                        target_remediation_state=ResourceState.REDACTED,
                        target_verification_state=ResourceState.REDACTED,
                        violation_reason=f"Retained record {category} contains exposed PII: {exposed_fields}",
                        exposed_prohibited_fields=exposed_fields
                    )
                else:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=True,
                        observed_state=ResourceState.REDACTED,
                        verification_operation=Operation.VERIFY_RECORD_REDACTED,
                        target_verification_state=ResourceState.REDACTED
                    )

        # =====================================================================
        # 3. Action: ANONYMIZE (Rule 07, 08)
        # =====================================================================
        elif action == "ANONYMIZE":
            is_anonymized = (observed_state == ResourceState.ANONYMIZED) and not has_prohibited_pii
            if not is_anonymized:
                return PolicyEvaluation(
                    category=category,
                    required_action=action,
                    is_compliant=False,
                    observed_state=ResourceState.PRESENT,
                    finding_operation=Operation.REPORT_EXPOSED_PII,
                    remediation_operation=Operation.ANONYMIZE_RECORD,
                    verification_operation=Operation.VERIFY_RECORD_ANONYMIZED,
                    target_remediation_state=ResourceState.ANONYMIZED,
                    target_verification_state=ResourceState.ANONYMIZED,
                    violation_reason=f"Profile {category} remains attributable to the user: {exposed_fields}",
                    exposed_prohibited_fields=exposed_fields
                )
            else:
                return PolicyEvaluation(
                    category=category,
                    required_action=action,
                    is_compliant=True,
                    observed_state=ResourceState.ANONYMIZED,
                    verification_operation=Operation.VERIFY_RECORD_ANONYMIZED,
                    target_verification_state=ResourceState.ANONYMIZED
                )

        # =====================================================================
        # 4. Action: RETAIN (Rule 12, 13, 14)
        # =====================================================================
        elif action == "RETAIN":
            if cat_upper == "BACKUP_ARCHIVE":
                # Rule 14: Retain archive, but restore access must be blocked
                restore_allowed = details.get("restore_allowed", False) or (observed_state == ResourceState.ACTIVE)
                if restore_allowed:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=False,
                        observed_state=ResourceState.ACTIVE,
                        finding_operation=Operation.REPORT_RESTORE_RISK,
                        remediation_operation=Operation.BLOCK_RESTORE,
                        verification_operation=Operation.VERIFY_RESTORE_BLOCKED,
                        target_remediation_state=ResourceState.BLOCKED,
                        target_verification_state=ResourceState.BLOCKED,
                        violation_reason="Backup archive is retained but restore access is not blocked"
                    )
                else:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=True,
                        observed_state=ResourceState.BLOCKED,
                        verification_operation=Operation.VERIFY_RESTORE_BLOCKED,
                        target_verification_state=ResourceState.BLOCKED
                    )

            else:
                # Security audit log, legal hold record
                if observed_state == ResourceState.ABSENT:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=False,
                        observed_state=ResourceState.ABSENT,
                        violation_reason=f"Mandatory retained record {category} is missing or deleted"
                    )
                else:
                    return PolicyEvaluation(
                        category=category,
                        required_action=action,
                        is_compliant=True,
                        observed_state=ResourceState.PRESENT,
                        verification_operation=Operation.VERIFY_RECORD_PRESENT,
                        target_verification_state=ResourceState.PRESENT
                    )

        # Default fallback should not be reached due to rule validation
        raise InvalidDataFormatError(f"Unsupported action '{action}' for category '{category}'")
