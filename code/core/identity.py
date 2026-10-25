"""Identity resolution module.
Resolves stable user_id values, current, and historical identifiers from
user_identities.csv and user_audit_log.csv with collision detection,
normalization, and full evidence provenance.
"""
import re
import hashlib
from typing import List, Dict, Optional, Set, Tuple, Any

from code.models import (
    IdentityEnvelope, IdentityResolutionResult, IdentityEvidenceItem,
    MatchType, MatchConfidence
)
from code.core.errors import InvalidDataFormatError
from code.core.logging_utils import get_logger, mask_email

logger = get_logger("IdentityResolver")

# Normalization helpers
def normalize_email(email: Optional[str]) -> str:
    """Normalizes email to trimmed lowercase."""
    if not email or not isinstance(email, str):
        return ""
    clean = email.strip().lower()
    return clean if "@" in clean else ""

def normalize_phone(phone: Optional[str]) -> str:
    """Normalizes phone number to canonical international format if possible."""
    if not phone or not isinstance(phone, str):
        return ""
    clean = phone.strip()
    # Keep leading plus, remove non-digits
    has_plus = clean.startswith("+")
    digits = re.sub(r'\D', '', clean)
    if not digits:
        return ""
    return f"+{digits}" if has_plus else digits

def normalize_hash(h: Optional[str]) -> str:
    """Normalizes SHA-256 hash to trimmed lowercase hex string."""
    if not h or not isinstance(h, str):
        return ""
    clean = h.strip().lower()
    return clean if len(clean) == 64 and all(c in "0123456789abcdef" for c in clean) else ""

def normalize_user_id(uid: Optional[str]) -> str:
    """Normalizes user_id."""
    if not uid or not isinstance(uid, str):
        return ""
    return uid.strip().lower()


class IdentityResolver:
    """Deterministic, collision-aware identity resolution engine."""

    def __init__(self, identities: List[Dict[str, str]], audit_logs: List[Dict[str, str]]):
        self.identities_by_user_id: Dict[str, Dict[str, str]] = {}
        self.current_email_to_uid: Dict[str, str] = {}
        self.historical_email_to_uids: Dict[str, Set[str]] = {}
        self.audit_logs_by_user_id: Dict[str, List[Dict[str, str]]] = {}
        self.phone_to_uids: Dict[str, Set[str]] = {}
        self.hash_to_uids: Dict[str, Set[str]] = {}

        self._build_indexes(identities, audit_logs)

    def _build_indexes(self, identities: List[Dict[str, str]], audit_logs: List[Dict[str, str]]) -> None:
        """Constructs forward and reverse indexes with collision tracking."""
        # 1. Index current identities snapshot
        for rec in identities:
            uid = normalize_user_id(rec.get("user_id"))
            if not uid:
                continue

            self.identities_by_user_id[uid] = rec
            em = normalize_email(rec.get("email"))
            if em:
                # Detect duplicate current email collision across distinct users
                if em in self.current_email_to_uid and self.current_email_to_uid[em] != uid:
                    logger.warning(f"Identity collision: Current email {mask_email(em)} claimed by both {self.current_email_to_uid[em]} and {uid}")
                self.current_email_to_uid[em] = uid

            ph = normalize_phone(rec.get("phone"))
            if ph:
                self.phone_to_uids.setdefault(ph, set()).add(uid)

            h = normalize_hash(rec.get("email_hash"))
            if h:
                self.hash_to_uids.setdefault(h, set()).add(uid)

        # 2. Index historical changes from user_audit_log
        for event in audit_logs:
            uid = normalize_user_id(event.get("user_id"))
            if not uid:
                continue

            self.audit_logs_by_user_id.setdefault(uid, []).append(event)
            field = event.get("field_name", "").strip().lower()
            old_val = event.get("old_value", "")
            new_val = event.get("new_value", "")

            if field == "email":
                for raw in [old_val, new_val]:
                    norm = normalize_email(raw)
                    if norm:
                        self.historical_email_to_uids.setdefault(norm, set()).add(uid)

            elif field == "phone":
                for raw in [old_val, new_val]:
                    norm = normalize_phone(raw)
                    if norm:
                        self.phone_to_uids.setdefault(norm, set()).add(uid)

            elif field == "email_hash":
                for raw in [old_val, new_val]:
                    norm = normalize_hash(raw)
                    if norm:
                        self.hash_to_uids.setdefault(norm, set()).add(uid)

    def resolve_identity(self, seed_email: str) -> IdentityResolutionResult:
        """Resolves seed email to a rich IdentityResolutionResult with evidence trail and collision detection."""
        norm_email = normalize_email(seed_email)
        if not norm_email:
            raise InvalidDataFormatError(f"Cannot resolve empty or invalid email: '{seed_email}'")

        evidence_trail: List[IdentityEvidenceItem] = []
        claimant_uids: Set[str] = set()

        # Step 1: Check current identities snapshot
        matched_current_uid = self.current_email_to_uid.get(norm_email)
        if matched_current_uid:
            claimant_uids.add(matched_current_uid)
            evidence_trail.append(IdentityEvidenceItem(
                source_file="user_identities.csv",
                source_record_id=matched_current_uid,
                field_name="email",
                matched_value=norm_email,
                event_time=self.identities_by_user_id.get(matched_current_uid, {}).get("updated_at"),
                description=f"Exact match on current email snapshot for user {matched_current_uid}"
            ))

        # Step 2: Check historical audit logs
        historical_uids = self.historical_email_to_uids.get(norm_email, set())
        for h_uid in historical_uids:
            claimant_uids.add(h_uid)
            # Find specific audit log row
            for event in self.audit_logs_by_user_id.get(h_uid, []):
                if event.get("field_name") == "email":
                    if normalize_email(event.get("old_value")) == norm_email or normalize_email(event.get("new_value")) == norm_email:
                        evidence_trail.append(IdentityEvidenceItem(
                            source_file="user_audit_log.csv",
                            source_record_id=event.get("audit_id", "unknown"),
                            field_name="email",
                            matched_value=norm_email,
                            event_time=event.get("event_time"),
                            description=f"Historical email match in audit log event {event.get('audit_id')} for user {h_uid}"
                        ))

        # Collision Check: If multiple distinct users claim the same email
        if len(claimant_uids) > 1:
            sorted_claimants = sorted(list(claimant_uids))
            logger.warning(f"Identity collision: Email {mask_email(norm_email)} is claimed by multiple users: {sorted_claimants}")
            return IdentityResolutionResult(
                envelope=None,
                match_type=MatchType.AMBIGUOUS_COLLISION,
                confidence=MatchConfidence.AMBIGUOUS,
                primary_user_id=None,
                evidence_trail=evidence_trail,
                collisions=sorted_claimants,
                is_ambiguous=True,
                is_registered=True
            )

        # Unseen / Unregistered Check
        if len(claimant_uids) == 0:
            seed_hash = hashlib.sha256(norm_email.encode()).hexdigest()
            fallback_envelope = IdentityEnvelope(
                user_id=f"unregistered_{seed_hash[:8]}",
                canonical_name="",
                emails={norm_email},
                phones=set(),
                email_hashes={seed_hash}
            )
            return IdentityResolutionResult(
                envelope=fallback_envelope,
                match_type=MatchType.UNRESOLVED,
                confidence=MatchConfidence.UNREGISTERED,
                primary_user_id=None,
                evidence_trail=[],
                collisions=[],
                is_ambiguous=False,
                is_registered=False
            )

        # Exactly 1 claimant user_id confirmed
        user_id = next(iter(claimant_uids))
        match_type = MatchType.EXACT_CURRENT_EMAIL if matched_current_uid else MatchType.EXACT_HISTORICAL_EMAIL
        envelope = self._build_envelope(user_id, norm_email)

        return IdentityResolutionResult(
            envelope=envelope,
            match_type=match_type,
            confidence=MatchConfidence.CONFIRMED,
            primary_user_id=user_id,
            evidence_trail=evidence_trail,
            collisions=[],
            is_ambiguous=False,
            is_registered=True
        )

    def _build_envelope(self, user_id: str, seed_email: str) -> IdentityEnvelope:
        """Constructs complete identity envelope with current and historical identifiers."""
        base_rec = self.identities_by_user_id.get(user_id, {})
        canonical_name = base_rec.get("name", "").strip()

        emails: Set[str] = set()
        phones: Set[str] = set()
        email_hashes: Set[str] = set()

        # Add seed email
        norm_seed = normalize_email(seed_email)
        if norm_seed:
            emails.add(norm_seed)
            email_hashes.add(hashlib.sha256(norm_seed.encode()).hexdigest())

        # Add current attributes
        cur_em = normalize_email(base_rec.get("email"))
        if cur_em:
            emails.add(cur_em)
            email_hashes.add(hashlib.sha256(cur_em.encode()).hexdigest())

        cur_ph = base_rec.get("phone", "").strip()
        if cur_ph:
            phones.add(cur_ph)
            norm_ph = normalize_phone(cur_ph)
            if norm_ph:
                phones.add(norm_ph)

        cur_h = normalize_hash(base_rec.get("email_hash"))
        if cur_h:
            email_hashes.add(cur_h)

        # Harvest historical changes from audit log
        for event in self.audit_logs_by_user_id.get(user_id, []):
            field = event.get("field_name", "").strip().lower()
            old_val = event.get("old_value", "").strip()
            new_val = event.get("new_value", "").strip()

            if field == "email":
                for raw in [old_val, new_val]:
                    norm = normalize_email(raw)
                    if norm:
                        emails.add(norm)
                        email_hashes.add(hashlib.sha256(norm.encode()).hexdigest())

            elif field == "phone":
                for raw in [old_val, new_val]:
                    if raw:
                        phones.add(raw)
                        norm_p = normalize_phone(raw)
                        if norm_p:
                            phones.add(norm_p)

            elif field == "email_hash":
                for raw in [old_val, new_val]:
                    norm_h = normalize_hash(raw)
                    if norm_h:
                        email_hashes.add(norm_h)

        return IdentityEnvelope(
            user_id=user_id,
            canonical_name=canonical_name,
            emails=emails,
            phones=phones,
            email_hashes=email_hashes
        )

    def resolve(self, seed_email: str) -> Optional[IdentityEnvelope]:
        """Convenience method returning Optional[IdentityEnvelope] for pipeline consumers."""
        try:
            result = self.resolve_identity(seed_email)
            return result.envelope
        except Exception as e:
            logger.error(f"Error resolving identity for {mask_email(seed_email)}: {e}")
            return None
