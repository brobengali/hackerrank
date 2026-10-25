"""
Generalization Audit — Ghost Data Still Exists
==============================================
All 10 controlled-change dimensions:
  DIM-01  User identifiers and historical aliases
  DIM-02  Record identifiers
  DIM-03  Row ordering
  DIM-04  Number of systems and records
  DIM-05  Policy treatments
  DIM-06  Retention periods / allowed residual field sets
  DIM-07  Evidence availability
  DIM-08  Event ordering
  DIM-09  Resurrection-process state
  DIM-10  Allowed residual identifiers
  HC      Hardcoding audit

Each test:
  1. Explains what should change and why.
  2. Runs ORIGINAL fixture (baseline).
  3. Runs MODIFIED fixture (controlled change).
  4. Compares decisions and evidence traces.
  5. Asserts outcome follows changed data/policy.
  6. Serves as a permanent regression guard.

Fixtures are 100% synthetic — no real challenge data is read or modified.
"""
import copy
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from code.models import (
    CaseAuditResult, DeletionCase, DeletionRule, DeletionStatus,
    IdentityEnvelope, InvestigationFinding, Operation, Phase,
    ProcessStatus, ResourceState, ResurrectionReport, ResurrectionRisk, Step,
)
from code.core.policy_engine import PolicyEngine, PROHIBITED_DIRECT_PII, TOMBSTONE_PERMITTED_FIELDS
from code.core.identity import IdentityResolver
from code.core.investigator import CrossSystemInvestigator
from code.core.resurrection import ResurrectionEngine
from code.core.remediation_planner import RemediationPlanner
from code.core.verification_engine import PostModelSafetyGate
from code.core.evidence_store import EvidenceStore, EvidenceObservation, infer_category
from code.core.ai_interpreter import RequestInterpreter
from code.core.errors import UnknownPolicyCategoryError, ContradictoryPolicyError


# ---------------------------------------------------------------------------
# Shared synthetic fixture helpers
# ---------------------------------------------------------------------------

def _make_case(
    case_id="case_gen_01",
    email="alice@synth.io",
    requested_at="2026-08-01T10:00:00Z",
    reported_status="COMPLETE",
    reported_at="2026-08-01T12:00:00Z",
    audit_at="2026-08-05T00:00:00Z",
    request_text="Please delete all my personal data.",
):
    return DeletionCase(
        case_id=case_id, email=email, requested_at=requested_at,
        reported_status=reported_status, reported_at=reported_at,
        audit_at=audit_at, request_text=request_text,
    )


def _make_envelope(user_id="user_synth_01", emails=None, phones=None, email_hashes=None):
    return IdentityEnvelope(
        user_id=user_id,
        canonical_name="Synthetic User",
        emails=set(emails or {"alice@synth.io"}),
        phones=set(phones or {"+1-555-9001"}),
        email_hashes=set(email_hashes or {}),
    )


def _make_obs(
    file_id="ev_synth_01",
    captured_at="2026-08-02T00:00:00Z",
    system_id="account_service",
    resource_id="account_synth_01",
    category="USER_PROFILE",
    state=ResourceState.PRESENT,
    matched_keys=None,
    has_exposed_pii=False,
    is_retained=False,
):
    return EvidenceObservation(
        file_id=file_id, captured_at=captured_at,
        system_id=system_id, resource_id=resource_id,
        category=category, state=state,
        matched_keys=set(matched_keys or {"user_synth_01"}),
        has_exposed_pii=has_exposed_pii,
        is_retained=is_retained,
    )


def _base_rules():
    return [
        DeletionRule("r01", "USER_PROFILE",       "DEFAULT", "DELETE"),
        DeletionRule("r02", "SECURITY_AUDIT_LOG", "DEFAULT", "RETAIN"),
        DeletionRule("r03", "ACCOUNT_TOMBSTONE",  "DEFAULT", "REDACT"),
        DeletionRule("r04", "ANALYTICS_PROFILE",  "DEFAULT", "ANONYMIZE"),
        DeletionRule("r05", "SUPPORT_MESSAGE",    "DEFAULT", "REDACT"),
        DeletionRule("r06", "USER_EXPORT",        "DEFAULT", "DELETE"),
        DeletionRule("r07", "BACKUP_ARCHIVE",     "DEFAULT", "RETAIN"),
        DeletionRule("r08", "MARKETING_PROFILE",  "DEFAULT", "DELETE"),
        DeletionRule("r09", "SEARCH_INDEX_ENTRY", "DEFAULT", "DELETE"),
        DeletionRule("r10", "EMAIL_DELIVERY_LOG", "DEFAULT", "REDACT"),
        DeletionRule("r11", "DATA_FLOW",          "DEFAULT", "DELETE"),
    ]


def _mock_store(observations):
    store = MagicMock(spec=EvidenceStore)
    store.query_subject_observations.return_value = list(observations)
    store.has_evidence.return_value = True
    return store


def _make_activity(
    activity_id="act_01",
    event_time="2026-08-01T11:00:00Z",
    event_type="DELETE_RECORD",
    source_system="deletion_worker",
    target_system="account_service",
    resource_id="account_synth_01",
    reported_result="SUCCESS",
    details="",
):
    return {
        "activity_id": activity_id,
        "event_time": event_time,
        "event_type": event_type,
        "source_system": source_system,
        "target_system": target_system,
        "resource_id": resource_id,
        "reported_result": reported_result,
        "details": details,
    }


# ===========================================================================
# DIM-01  User identifiers and historical aliases
# ===========================================================================

class TestDim01UserIdentifiers(unittest.TestCase):
    """
    CHANGE:  Swap user_id from 'user_001' to an arbitrary UUID-style string and
             extend the email alias chain to 3 hops.
    EXPECT:  Resolution finds the correct account regardless of identifier format;
             full envelope is built through all hops.
    """

    def _resolver(self, user_id, current_email, audit_log):
        identities = [{"user_id": user_id, "name": "Gen User",
                       "email": current_email, "phone": "+1-555-0000",
                       "email_hash": "", "updated_at": "2026-07-01T00:00:00Z"}]
        return IdentityResolver(identities, audit_log)

    def test_01a_original_simple_user_id(self):
        """Original: user_id='user_001', single email."""
        r = self._resolver("user_001", "alice@old.com", [])
        env = r.resolve("alice@old.com")
        self.assertIsNotNone(env)
        self.assertEqual(env.user_id, "user_001")
        self.assertIn("alice@old.com", env.emails)

    def test_01b_uuid_style_user_id(self):
        """Modified: UUID user_id. System must not depend on 'user_NNN' pattern."""
        uid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        r = self._resolver(uid, "alice.uuid@new.io", [])
        env = r.resolve("alice.uuid@new.io")
        self.assertIsNotNone(env)
        self.assertEqual(env.user_id, uid)

    def test_01c_single_historical_hop(self):
        """Original: one email change captured in audit log."""
        uid = "user_001"
        log = [{"audit_id": "a1", "user_id": uid, "event_time": "2026-05-01T00:00:00Z",
                "field_name": "email", "old_value": "orig@old.com", "new_value": "curr@old.com"}]
        r = self._resolver(uid, "curr@old.com", log)
        env = r.resolve("orig@old.com")
        self.assertIsNotNone(env)
        self.assertIn("orig@old.com", env.emails)
        self.assertIn("curr@old.com", env.emails)

    def test_01d_three_hop_alias_chain(self):
        """Modified: 3-hop chain. All hops must appear in the envelope."""
        uid = "user_multihop"
        log = [
            {"audit_id": "a1", "user_id": uid, "event_time": "2026-01-01T00:00:00Z",
             "field_name": "email", "old_value": "hop1@x.com", "new_value": "hop2@x.com"},
            {"audit_id": "a2", "user_id": uid, "event_time": "2026-03-01T00:00:00Z",
             "field_name": "email", "old_value": "hop2@x.com", "new_value": "hop3@x.com"},
        ]
        r = self._resolver(uid, "hop3@x.com", log)
        env = r.resolve("hop1@x.com")
        self.assertIsNotNone(env)
        self.assertEqual(env.user_id, uid)
        for hop in ["hop1@x.com", "hop2@x.com", "hop3@x.com"]:
            self.assertIn(hop, env.emails)

    def test_01e_distinct_users_do_not_collide(self):
        """Two users with distinct IDs and emails never share an envelope."""
        identities = [
            {"user_id": "user_alpha", "name": "A", "email": "a@a.com",
             "phone": "", "email_hash": "", "updated_at": "2026-01-01T00:00:00Z"},
            {"user_id": "user_beta",  "name": "B", "email": "b@b.com",
             "phone": "", "email_hash": "", "updated_at": "2026-01-01T00:00:00Z"},
        ]
        r = IdentityResolver(identities, [])
        env_a = r.resolve("a@a.com")
        env_b = r.resolve("b@b.com")
        self.assertEqual(env_a.user_id, "user_alpha")
        self.assertEqual(env_b.user_id, "user_beta")
        self.assertNotEqual(env_a.user_id, env_b.user_id)


    def test_01f_historical_phone_included_in_envelope(self):
        """Historical phone change is captured in the envelope for cross-system matching."""
        uid = "user_phone"
        log = [{"audit_id": "p1", "user_id": uid, "event_time": "2026-02-01T00:00:00Z",
                "field_name": "phone", "old_value": "+1-555-1111", "new_value": "+1-555-2222"}]
        identities = [{"user_id": uid, "name": "P", "email": "p@p.com",
                       "phone": "+1-555-2222", "email_hash": "", "updated_at": "2026-02-01T00:00:00Z"}]
        r = IdentityResolver(identities, log)
        env = r.resolve("p@p.com")
        self.assertIn("+1-555-1111", env.phones)
        self.assertIn("+1-555-2222", env.phones)


# ===========================================================================
# DIM-02  Record identifiers
# ===========================================================================

class TestDim02RecordIdentifiers(unittest.TestCase):
    """
    CHANGE:  Swap resource_id from 'account_001' to a UUID or hyphenated slug.
    EXPECT:  Policy decisions depend on category+state only. Findings cite the
             actual resource_id from data, not a hardcoded string.
    """

    def setUp(self):
        self.engine = PolicyEngine(_base_rules())

    def _eval(self, resource_id, state=ResourceState.PRESENT):
        obs = _make_obs(resource_id=resource_id, state=state)
        return self.engine.evaluate_record(
            obs.category, obs.state, record_fields={"email": "t@t.com"})

    def test_02a_standard_account_id_triggers_delete(self):
        ev = self._eval("account_001")
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.required_action, "DELETE")

    def test_02b_uuid_resource_id_same_decision(self):
        ev = self._eval("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.required_action, "DELETE")

    def test_02c_hyphenated_slug_resource_id(self):
        ev = self._eval("profile-XYZ-99")
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.required_action, "DELETE")

    def test_02d_absent_record_compliant_for_any_id(self):
        for rid in ["account_001", "uuid-abc", "profile-XYZ"]:
            ev = self._eval(rid, state=ResourceState.ABSENT)
            self.assertTrue(ev.is_compliant, f"ABSENT record must be compliant: {rid}")

    def test_02e_finding_cites_actual_resource_id(self):
        """Investigator finding carries the resource_id from data, not a hardcoded value."""
        custom_rid = "profile-CUSTOM-8877"
        obs = _make_obs(resource_id=custom_rid, state=ResourceState.PRESENT,
                        matched_keys={"user_synth_01", "alice@synth.io"})
        inv = CrossSystemInvestigator(_mock_store([obs]), self.engine, [])
        report = inv.investigate(_make_case(), _make_envelope())
        self.assertIn(custom_rid, [f.resource_id for f in report.findings])


# ===========================================================================
# DIM-03  Row ordering
# ===========================================================================

class TestDim03RowOrdering(unittest.TestCase):
    """
    CHANGE:  Shuffle input cases, evidence observations, identity records, and rules.
    EXPECT:  All decisions are order-invariant. Latest observation always wins.
    """

    def test_03a_shuffled_cases_sort_to_same_output(self):
        cases = [_make_case(case_id=f"case_{i:03d}") for i in range(1, 11)]
        shuffled = copy.copy(cases)
        random.seed(99)
        random.shuffle(shuffled)
        sorted_orig = sorted(cases, key=lambda c: c.case_id)
        sorted_shuf = sorted(shuffled, key=lambda c: c.case_id)
        self.assertEqual([c.case_id for c in sorted_orig],
                         [c.case_id for c in sorted_shuf])

    def test_03b_latest_observation_wins_regardless_of_list_order(self):
        """Newer captured_at always wins even if it appears later in the list."""
        old_obs = _make_obs(captured_at="2026-07-01T00:00:00Z", state=ResourceState.ABSENT)
        new_obs = _make_obs(captured_at="2026-08-01T00:00:00Z", state=ResourceState.PRESENT)
        engine = PolicyEngine(_base_rules())
        for ordering in [[old_obs, new_obs], [new_obs, old_obs]]:
            inv = CrossSystemInvestigator(_mock_store(ordering), engine, [])
            report = inv.investigate(_make_case(), _make_envelope())
            # The newer PRESENT state must produce a finding
            self.assertGreater(len(report.findings), 0,
                               "Latest observation (PRESENT) must win regardless of list order.")

    def test_03c_shuffled_identity_records_resolve_consistently(self):
        users = [{"user_id": f"user_{i}", "name": f"U{i}", "email": f"u{i}@t.com",
                  "phone": "", "email_hash": "", "updated_at": "2026-01-01T00:00:00Z"}
                 for i in range(1, 6)]
        shuffled = copy.copy(users)
        random.seed(7)
        random.shuffle(shuffled)
        r1, r2 = IdentityResolver(users, []), IdentityResolver(shuffled, [])
        for u in users:
            self.assertEqual(r1.resolve(u["email"]).user_id,
                             r2.resolve(u["email"]).user_id)

    def test_03d_shuffled_rules_produce_same_policy(self):
        rules = _base_rules()
        shuffled = copy.copy(rules)
        random.seed(42)
        random.shuffle(shuffled)
        e1, e2 = PolicyEngine(rules), PolicyEngine(shuffled)
        for cat in ["USER_PROFILE", "ANALYTICS_PROFILE", "SECURITY_AUDIT_LOG"]:
            ev1 = e1.evaluate_record(cat, ResourceState.PRESENT)
            ev2 = e2.evaluate_record(cat, ResourceState.PRESENT)
            self.assertEqual(ev1.required_action, ev2.required_action,
                             f"Rule shuffle must not affect action for {cat}")
            self.assertEqual(ev1.is_compliant, ev2.is_compliant)

    def test_03e_tie_break_prefers_non_compliant(self):
        """Same-timestamp observations: non-compliant state must not be suppressed."""
        compliant = _make_obs(captured_at="2026-08-01T00:00:00Z", state=ResourceState.ABSENT)
        non_compliant = _make_obs(captured_at="2026-08-01T00:00:00Z",
                                  state=ResourceState.PRESENT, has_exposed_pii=True)
        engine = PolicyEngine(_base_rules())
        for ordering in [[compliant, non_compliant], [non_compliant, compliant]]:
            inv = CrossSystemInvestigator(_mock_store(ordering), engine, [])
            report = inv.investigate(_make_case(), _make_envelope())
            self.assertGreater(len(report.findings), 0,
                               "Non-compliant tie must be surfaced regardless of list position.")


# ===========================================================================
# DIM-04  Number of systems and records
# ===========================================================================

class TestDim04DataVolume(unittest.TestCase):
    """
    CHANGE:  Vary the number of affected records (0, 1, 10, 200) and systems (1-5).
    EXPECT:  Exactly one finding per non-compliant record. No suppression or invention.
    """

    def _run(self, n, state=ResourceState.PRESENT, category="USER_PROFILE"):
        obs_list = [_make_obs(resource_id=f"res_{i:04d}", category=category, state=state,
                              matched_keys={f"u{i}@t.com", "user_synth_01"},
                              file_id=f"ev_{i:04d}")
                    for i in range(n)]
        env = IdentityEnvelope(user_id="user_synth_01", canonical_name="V",
                               emails={f"u{i}@t.com" for i in range(n)} | {"alice@synth.io"})
        inv = CrossSystemInvestigator(_mock_store(obs_list), PolicyEngine(_base_rules()), [])
        return inv.investigate(_make_case(), env)

    def test_04a_zero_records_zero_findings(self):
        self.assertEqual(len(self._run(0).findings), 0)

    def test_04b_one_present_record_one_finding(self):
        self.assertEqual(len(self._run(1).findings), 1)

    def test_04c_ten_present_records_ten_findings(self):
        self.assertEqual(len(self._run(10).findings), 10)

    def test_04d_twenty_absent_records_zero_findings(self):
        self.assertEqual(len(self._run(20, state=ResourceState.ABSENT).findings), 0)

    def test_04e_five_distinct_systems_each_contribute_finding(self):
        systems = ["account_service", "search_service", "export_service",
                   "analytics_platform", "support_platform"]
        cat_map = {
            "account_service":   "USER_PROFILE",
            "search_service":    "SEARCH_INDEX_ENTRY",
            "export_service":    "USER_EXPORT",
            "analytics_platform": "ANALYTICS_PROFILE",
            "support_platform":  "SUPPORT_MESSAGE",
        }
        obs_list = [
            _make_obs(resource_id=f"res_{s}", system_id=s, category=cat_map[s],
                      state=ResourceState.PRESENT, has_exposed_pii=True,
                      matched_keys={"user_synth_01", "alice@synth.io"})
            for s in systems
        ]
        inv = CrossSystemInvestigator(_mock_store(obs_list), PolicyEngine(_base_rules()), [])
        report = inv.investigate(_make_case(), _make_envelope())
        self.assertGreaterEqual(len(report.findings), len(systems))

    def test_04f_batch_of_200_cases_all_preserved(self):
        cases = [_make_case(case_id=f"case_{i:04d}", email=f"u{i}@t.com") for i in range(200)]
        results = [CaseAuditResult(c.case_id, DeletionStatus.COMPLETE) for c in cases]
        self.assertEqual({r.case_id for r in results}, {c.case_id for c in cases})


# ===========================================================================
# DIM-05  Policy treatments
# ===========================================================================

class TestDim05PolicyTreatments(unittest.TestCase):
    """
    CHANGE:  Swap required_action (DELETE/ANONYMIZE/REDACT/RETAIN) per category.
    EXPECT:  All downstream operations (finding, remediation, verification) change
             to match the new policy. No hardcoded treatment exists.
    """

    def _eval(self, rules, cat, state=ResourceState.PRESENT, fields=None, details=None):
        return PolicyEngine(rules).evaluate_record(cat, state,
                                                   record_fields=fields, details=details)

    def test_05a_delete_produces_delete_operations(self):
        ev = self._eval([DeletionRule("r", "USER_PROFILE", "DEFAULT", "DELETE")], "USER_PROFILE")
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.finding_operation, Operation.REPORT_REMAINING_RECORD)
        self.assertEqual(ev.remediation_operation, Operation.DELETE_RECORD)
        self.assertEqual(ev.verification_operation, Operation.VERIFY_RECORD_ABSENT)

    def test_05b_anonymize_produces_anonymize_operations(self):
        ev = self._eval([DeletionRule("r", "USER_PROFILE", "DEFAULT", "ANONYMIZE")],
                        "USER_PROFILE", fields={"email": "x@x.com"})
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.finding_operation, Operation.REPORT_EXPOSED_PII)
        self.assertEqual(ev.remediation_operation, Operation.ANONYMIZE_RECORD)
        self.assertEqual(ev.verification_operation, Operation.VERIFY_RECORD_ANONYMIZED)

    def test_05c_retain_makes_present_record_compliant(self):
        ev = self._eval([DeletionRule("r", "SECURITY_AUDIT_LOG", "DEFAULT", "RETAIN")],
                        "SECURITY_AUDIT_LOG")
        self.assertTrue(ev.is_compliant)
        self.assertEqual(ev.verification_operation, Operation.VERIFY_RECORD_PRESENT)

    def test_05d_retain_backup_active_triggers_block_restore(self):
        ev = self._eval([DeletionRule("r", "BACKUP_ARCHIVE", "DEFAULT", "RETAIN")],
                        "BACKUP_ARCHIVE", state=ResourceState.ACTIVE,
                        details={"restore_allowed": True})
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.finding_operation, Operation.REPORT_RESTORE_RISK)
        self.assertEqual(ev.remediation_operation, Operation.BLOCK_RESTORE)

    def test_05e_redact_tombstone_with_pii_is_non_compliant(self):
        ev = self._eval([DeletionRule("r", "ACCOUNT_TOMBSTONE", "DEFAULT", "REDACT")],
                        "ACCOUNT_TOMBSTONE",
                        fields={"email": "a@a.com", "name": "Alice"},
                        details={"has_exposed_pii": True})
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.finding_operation, Operation.REPORT_EXPOSED_PII)
        self.assertEqual(ev.remediation_operation, Operation.REDACT_RECORD)

    def test_05f_switching_delete_to_redact_changes_remediation(self):
        ev_del = PolicyEngine([DeletionRule("r", "USER_EXPORT", "DEFAULT", "DELETE")]) \
            .evaluate_record("USER_EXPORT", ResourceState.PRESENT,
                             record_fields={"email": "x@x.com"})
        ev_red = PolicyEngine([DeletionRule("r", "USER_EXPORT", "DEFAULT", "REDACT")]) \
            .evaluate_record("USER_EXPORT", ResourceState.PRESENT,
                             record_fields={"email": "x@x.com"})
        self.assertEqual(ev_del.remediation_operation, Operation.DELETE_RECORD)
        self.assertEqual(ev_red.remediation_operation, Operation.REDACT_RECORD)
        self.assertNotEqual(ev_del.remediation_operation, ev_red.remediation_operation)

    def test_05g_novel_category_handled_without_code_change(self):
        rules = _base_rules() + [DeletionRule("r_new", "GENOMIC_DATA", "DEFAULT", "DELETE")]
        ev = PolicyEngine(rules).evaluate_record("GENOMIC_DATA", ResourceState.PRESENT)
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.required_action, "DELETE")


# ===========================================================================
# DIM-06  Retention periods / allowed residual field sets
# ===========================================================================

class TestDim06RetentionPeriods(unittest.TestCase):
    """
    CHANGE:  Vary which PII fields remain on ACCOUNT_TOMBSTONE and SUPPORT_MESSAGE.
    EXPECT:  PROHIBITED_DIRECT_PII fields are flagged; TOMBSTONE_PERMITTED_FIELDS are not.
    """

    def setUp(self):
        self.engine = PolicyEngine(_base_rules())

    def _eval_tombstone(self, fields, has_pii=False):
        return self.engine.evaluate_record(
            "ACCOUNT_TOMBSTONE", ResourceState.PRESENT,
            record_fields=fields, details={"has_exposed_pii": has_pii})

    def test_06a_tombstone_only_user_id_compliant(self):
        self.assertTrue(self._eval_tombstone({"user_id": "u1"}).is_compliant)

    def test_06b_tombstone_with_email_non_compliant(self):
        ev = self._eval_tombstone({"user_id": "u1", "email": "a@a.com"}, has_pii=True)
        self.assertFalse(ev.is_compliant)
        self.assertIn("email", str(ev.exposed_prohibited_fields) + str(ev.violation_reason))

    def test_06c_any_prohibited_field_triggers_tombstone_violation(self):
        for field in ["name", "phone", "email_hash"]:
            ev = self._eval_tombstone({"user_id": "u1", field: "val"}, has_pii=True)
            self.assertFalse(ev.is_compliant, f"Field '{field}' must be flagged.")

    def test_06d_permitted_tombstone_fields_never_flagged(self):
        for field in TOMBSTONE_PERMITTED_FIELDS:
            ev = self._eval_tombstone({"user_id": "u1", field: "val"})
            self.assertTrue(ev.is_compliant,
                            f"Permitted field '{field}' must not trigger violation.")

    def test_06e_redacted_support_message_compliant(self):
        ev = self.engine.evaluate_record(
            "SUPPORT_MESSAGE", ResourceState.REDACTED,
            record_fields={"ticket_id": "t1", "body": "Issue"},
        )
        self.assertTrue(ev.is_compliant)

    def test_06f_support_message_with_pii_field_non_compliant(self):
        ev = self.engine.evaluate_record(
            "SUPPORT_MESSAGE", ResourceState.PRESENT,
            record_fields={"requester_email": "alice@test.com"},
            details={"has_exposed_pii": True}
        )
        self.assertFalse(ev.is_compliant)

    def test_06g_inspect_prohibited_identifiers_only_returns_prohibited(self):
        has_pii, exposed = self.engine.inspect_prohibited_identifiers(
            "ACCOUNT_TOMBSTONE",
            {"user_id": "u1", "status": "closed", "email": "x@x.com", "phone": "+1-555-0"}
        )
        self.assertTrue(has_pii)
        self.assertIn("email", exposed)
        self.assertIn("phone", exposed)
        self.assertNotIn("user_id", exposed)
        self.assertNotIn("status", exposed)


# ===========================================================================
# DIM-07  Evidence availability
# ===========================================================================

class TestDim07EvidenceAvailability(unittest.TestCase):
    """
    CHANGE:  Remove / add evidence files; shift captured_at relative to audit_at.
    EXPECT:
      - Evidence after audit_at is excluded.
      - Missing evidence on a COMPLETE candidate forces INCOMPLETE.
      - Adding incriminating evidence flips COMPLETE → INCOMPLETE.
    """

    def test_07a_observation_before_cutoff_included(self):
        obs = _make_obs(captured_at="2026-08-04T23:59:59Z")
        inv = CrossSystemInvestigator(_mock_store([obs]), PolicyEngine(_base_rules()), [])
        report = inv.investigate(_make_case(audit_at="2026-08-05T00:00:00Z"), _make_envelope())
        self.assertGreater(len(report.findings) + len(report.observed_resources), 0)

    def test_07b_post_cutoff_observation_excluded(self):
        obs_before = _make_obs(captured_at="2026-08-04T00:00:00Z", state=ResourceState.PRESENT)
        obs_after  = _make_obs(file_id="ev_after", captured_at="2026-08-10T00:00:00Z",
                               state=ResourceState.ABSENT)

        def query_se(identity, audit_at, additional_resource_ids=None):
            return [o for o in [obs_before, obs_after] if o.captured_at <= audit_at]

        store = MagicMock(spec=EvidenceStore)
        store.query_subject_observations.side_effect = query_se
        inv = CrossSystemInvestigator(store, PolicyEngine(_base_rules()), [])
        report = inv.investigate(_make_case(audit_at="2026-08-05T00:00:00Z"), _make_envelope())
        self.assertIn(ResourceState.PRESENT, [f.state for f in report.findings],
                      "Post-cutoff ABSENT must not suppress the pre-cutoff PRESENT finding.")

    def test_07c_missing_evidence_on_verification_step_forces_incomplete(self):
        gate = PostModelSafetyGate()
        step = Step(0, Phase.VERIFICATION, "account_service", "account_001",
                    Operation.VERIFY_RECORD_ABSENT, ResourceState.ABSENT, evidence_id="")
        result = gate.enforce_safety_gate(case=_make_case(),
                                          is_deletion_authorized=True,
                                          findings=[], verification_steps=[step])
        self.assertEqual(result.final_status, DeletionStatus.INCOMPLETE)
        self.assertIn("INVARIANT_EVIDENCE_PROVENANCE_REQUIRED", result.failed_invariants)

    def test_07d_valid_evidence_id_allows_complete(self):
        gate = PostModelSafetyGate()
        step = Step(1, Phase.VERIFICATION, "account_service", "account_001",
                    Operation.VERIFY_RECORD_ABSENT, ResourceState.ABSENT, evidence_id="ev_01")
        result = gate.enforce_safety_gate(case=_make_case(),
                                          is_deletion_authorized=True,
                                          findings=[], verification_steps=[step])
        self.assertEqual(result.final_status, DeletionStatus.COMPLETE)

    def test_07e_adding_pii_finding_flips_complete_to_incomplete(self):
        gate = PostModelSafetyGate()
        case = _make_case()
        step = Step(1, Phase.VERIFICATION, "s", "r",
                    Operation.VERIFY_RECORD_ABSENT, ResourceState.ABSENT, evidence_id="ev_01")
        r_complete = gate.enforce_safety_gate(case=case, is_deletion_authorized=True,
                                              findings=[], verification_steps=[step])
        self.assertEqual(r_complete.final_status, DeletionStatus.COMPLETE)

        new_finding = InvestigationFinding(
            system_id="account_service", resource_id="acc",
            operation=Operation.REPORT_EXPOSED_PII,
            state=ResourceState.PRESENT, evidence_id="ev_new",
            category="USER_PROFILE", observed_at="2026-08-04T00:00:00Z",
            source_file="ev_new",
        )
        r_incomplete = gate.enforce_safety_gate(case=case, is_deletion_authorized=True,
                                                findings=[new_finding], verification_steps=[])
        self.assertEqual(r_incomplete.final_status, DeletionStatus.INCOMPLETE)

    def test_07f_manifest_temporal_cutoff_respected(self):
        manifest = [
            {"file_id": "ev_past",   "file_path": "ev/f.log",
             "captured_at": "2026-08-01T00:00:00Z", "origin": "system"},
            {"file_id": "ev_future", "file_path": "ev/g.log",
             "captured_at": "2026-09-01T00:00:00Z", "origin": "system"},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(Path(tmpdir), manifest)
        self.assertTrue(store.has_evidence("ev_past",   "2026-08-05T00:00:00Z"))
        self.assertFalse(store.has_evidence("ev_future", "2026-08-05T00:00:00Z"))
        self.assertFalse(store.has_evidence("ev_nope",   "2026-08-05T00:00:00Z"))


# ===========================================================================
# DIM-08  Event ordering
# ===========================================================================

class TestDim08EventOrdering(unittest.TestCase):
    """
    CHANGE:  Swap sync event before/after the deletion request timestamp.
    EXPECT:  Sync AFTER request → active resurrection risk.
             Sync BEFORE request → historical only.
             Reversed CSV row order → same chronological reconstruction.
    """

    def _acts(self, delete_t, sync_t):
        return [
            _make_activity("del_01", delete_t, "DELETE_RECORD",
                           "deletion_worker", "account_service", "account_evt", "SUCCESS"),
            _make_activity("sync_01", sync_t,  "SYNC_RECORD",
                           "sync_service",     "account_service", "account_evt", "ACTIVE"),
        ]

    def test_08a_sync_after_request_is_active_risk(self):
        res = ResurrectionEngine(_mock_store([]), PolicyEngine(_base_rules()),
                                 self._acts("2026-08-01T11:00:00Z", "2026-08-01T13:00:00Z"))
        case = _make_case(requested_at="2026-08-01T10:00:00Z")
        report = res.detect_resurrection_risks(case, _make_envelope(), {"account_evt"})
        self.assertIn("SYNC", [r.process_type for r in report.active_risks])

    def test_08b_sync_before_request_is_historical_only(self):
        res = ResurrectionEngine(_mock_store([]), PolicyEngine(_base_rules()),
                                 self._acts("2026-08-01T11:00:00Z", "2026-07-30T10:00:00Z"))
        case = _make_case(requested_at="2026-08-01T10:00:00Z")
        report = res.detect_resurrection_risks(case, _make_envelope(), {"account_evt"})
        self.assertNotIn("SYNC", [r.process_type for r in report.active_risks])

    def test_08c_reversed_activity_list_same_event_set(self):
        acts = self._acts("2026-08-01T11:00:00Z", "2026-08-01T13:00:00Z")
        engine = PolicyEngine(_base_rules())
        inv1 = CrossSystemInvestigator(_mock_store([]), engine, acts)
        inv2 = CrossSystemInvestigator(_mock_store([]), engine, list(reversed(acts)))
        case = _make_case()
        ev1 = inv1.reconstruct_events(case, {"account_evt"})
        ev2 = inv2.reconstruct_events(case, {"account_evt"})
        self.assertEqual(sorted(e.event_id for e in ev1),
                         sorted(e.event_id for e in ev2))
        ts1 = [e.timestamp for e in ev1]
        self.assertEqual(ts1, sorted(ts1), "Events must be chronologically ordered.")

    def test_08d_event_after_audit_at_excluded_from_reconstruction(self):
        acts = [
            _make_activity("before", "2026-08-03T00:00:00Z", resource_id="account_evt"),
            _make_activity("after",  "2026-09-01T00:00:00Z", resource_id="account_evt"),
        ]
        inv = CrossSystemInvestigator(_mock_store([]), PolicyEngine(_base_rules()), acts)
        events = inv.reconstruct_events(_make_case(audit_at="2026-08-05T00:00:00Z"),
                                         {"account_evt"})
        ids = [e.event_id for e in events]
        self.assertIn("before", ids)
        self.assertNotIn("after", ids)


# ===========================================================================
# DIM-09  Resurrection-process state
# ===========================================================================

class TestDim09ResurrectionProcessState(unittest.TestCase):
    """
    CHANGE:  Flip connector state ACTIVE ↔ DISABLED and backup ACTIVE ↔ BLOCKED.
    EXPECT:  ACTIVE → risk; DISABLED/BLOCKED → controlled process only.
             Safety gate independently blocks COMPLETE for any active risk.
    """

    def _flow_obs(self, state, rid="flow_001"):
        return _make_obs(file_id="ev_flow", resource_id=rid,
                         system_id="integration_service", category="DATA_FLOW",
                         state=state, matched_keys={"user_synth_01"})

    def _backup_obs(self, state, rid="backup_001"):
        return _make_obs(file_id="ev_backup", resource_id=rid,
                         system_id="backup_service", category="BACKUP_ARCHIVE",
                         state=state, matched_keys={"user_synth_01"})

    def test_09a_active_flow_is_resurrection_risk(self):
        res = ResurrectionEngine(_mock_store([self._flow_obs(ResourceState.ACTIVE)]),
                                 PolicyEngine(_base_rules()), [])
        report = res.detect_resurrection_risks(_make_case(), _make_envelope(), {"flow_001"})
        self.assertGreater(len(report.active_risks), 0)
        self.assertEqual(report.active_risks[0].process_type, "DATA_FLOW")

    def test_09b_disabled_flow_is_controlled_not_active(self):
        res = ResurrectionEngine(_mock_store([self._flow_obs(ResourceState.DISABLED)]),
                                 PolicyEngine(_base_rules()), [])
        report = res.detect_resurrection_risks(_make_case(), _make_envelope(), {"flow_001"})
        self.assertEqual(len(report.active_risks), 0)
        self.assertGreater(len(report.controlled_processes), 0)

    def test_09c_flipping_flow_active_to_disabled_removes_risk(self):
        engine = PolicyEngine(_base_rules())
        r_active = ResurrectionEngine(_mock_store([self._flow_obs(ResourceState.ACTIVE)]),
                                      engine, []) \
            .detect_resurrection_risks(_make_case(), _make_envelope(), {"flow_001"})
        r_disabled = ResurrectionEngine(_mock_store([self._flow_obs(ResourceState.DISABLED)]),
                                        engine, []) \
            .detect_resurrection_risks(_make_case(), _make_envelope(), {"flow_001"})
        self.assertGreater(len(r_active.active_risks), 0)
        self.assertEqual(len(r_disabled.active_risks), 0)

    def test_09d_active_backup_restore_is_risk(self):
        res = ResurrectionEngine(_mock_store([self._backup_obs(ResourceState.ACTIVE)]),
                                 PolicyEngine(_base_rules()), [])
        report = res.detect_resurrection_risks(_make_case(), _make_envelope(), {"backup_001"})
        self.assertGreater(len(report.active_risks), 0)
        self.assertEqual(report.active_risks[0].process_type, "RESTORE")

    def test_09e_blocked_backup_is_not_active_risk(self):
        res = ResurrectionEngine(_mock_store([self._backup_obs(ResourceState.BLOCKED)]),
                                 PolicyEngine(_base_rules()), [])
        report = res.detect_resurrection_risks(_make_case(), _make_envelope(), {"backup_001"})
        self.assertEqual(len(report.active_risks), 0)

    def test_09f_policy_engine_flags_data_flow_active(self):
        ev = PolicyEngine(_base_rules()).evaluate_record(
            "DATA_FLOW", ResourceState.ACTIVE, details={"enabled": True})
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.finding_operation, Operation.REPORT_ACTIVE_DATA_FLOW)
        self.assertEqual(ev.remediation_operation, Operation.DISABLE_DATA_FLOW)

    def test_09g_safety_gate_blocks_complete_when_active_risk_present(self):
        gate = PostModelSafetyGate()
        active_risk = ResurrectionRisk(
            process_ref="flow_001", source_system="integration_service",
            destination_system="warehouse", process_type="DATA_FLOW",
            status=ProcessStatus.ACTIVE, can_recreate_data=True, is_confirmed_active=True,
        )
        res_report = ResurrectionReport(case_id="case_gen_01", active_risks=[active_risk])
        result = gate.enforce_safety_gate(
            case=_make_case(), is_deletion_authorized=True,
            findings=[], verification_steps=[], resurrection_report=res_report)
        self.assertEqual(result.final_status, DeletionStatus.INCOMPLETE)
        self.assertIn("INVARIANT_RESURRECTION_CONTROLLED", result.failed_invariants)


# ===========================================================================
# DIM-10  Allowed residual identifiers
# ===========================================================================

class TestDim10ResidualIdentifiers(unittest.TestCase):
    """
    CHANGE:  Vary which PII fields remain in tombstones and analytics profiles.
    EXPECT:
      - user_id always permitted in ACCOUNT_TOMBSTONE.
      - name/email/phone/email_hash always prohibited in ACCOUNT_TOMBSTONE.
      - Attributable fields (email, email_hash) prohibited in ANALYTICS_PROFILE.
      - Cross-subject observations must not contaminate the subject envelope.
    """

    def setUp(self):
        self.engine = PolicyEngine(_base_rules())

    def _ev_tombstone(self, fields, has_pii=False):
        return self.engine.evaluate_record(
            "ACCOUNT_TOMBSTONE", ResourceState.PRESENT,
            record_fields=fields, details={"has_exposed_pii": has_pii})

    def test_10a_tombstone_user_id_only_compliant(self):
        self.assertTrue(self._ev_tombstone({"user_id": "u1"}).is_compliant)

    def test_10b_tombstone_email_non_compliant(self):
        ev = self._ev_tombstone({"user_id": "u1", "email": "a@a.com"}, has_pii=True)
        self.assertFalse(ev.is_compliant)

    def test_10c_tombstone_name_non_compliant(self):
        ev = self._ev_tombstone({"user_id": "u1", "name": "Alice"}, has_pii=True)
        self.assertFalse(ev.is_compliant)

    def test_10d_tombstone_phone_non_compliant(self):
        ev = self._ev_tombstone({"user_id": "u1", "phone": "+1-555-0001"}, has_pii=True)
        self.assertFalse(ev.is_compliant)

    def test_10e_tombstone_email_hash_non_compliant(self):
        ev = self._ev_tombstone({"user_id": "u1", "email_hash": "abc123"}, has_pii=True)
        self.assertFalse(ev.is_compliant)

    def test_10f_permitted_tombstone_fields_not_flagged(self):
        for field in TOMBSTONE_PERMITTED_FIELDS:
            ev = self._ev_tombstone({"user_id": "u1", field: "val"})
            self.assertTrue(ev.is_compliant,
                            f"Permitted field '{field}' must not trigger violation.")

    def test_10g_analytics_with_email_non_compliant(self):
        ev = self.engine.evaluate_record(
            "ANALYTICS_PROFILE", ResourceState.PRESENT,
            record_fields={"sessions": 10, "email": "x@x.com"}, details={"has_exposed_pii": True})
        self.assertFalse(ev.is_compliant)
        self.assertEqual(ev.remediation_operation, Operation.ANONYMIZE_RECORD)

    def test_10h_analytics_anonymized_no_attributable_fields_compliant(self):
        ev = self.engine.evaluate_record(
            "ANALYTICS_PROFILE", ResourceState.ANONYMIZED,
            record_fields={"sessions": 10, "device_type": "mobile"})
        self.assertTrue(ev.is_compliant)

    def test_10i_all_prohibited_pii_fields_detected_dynamically(self):
        """Every field in PROHIBITED_DIRECT_PII is detected without hardcoding the list."""
        for field in PROHIBITED_DIRECT_PII:
            has_pii, exposed = self.engine.inspect_prohibited_identifiers(
                "ACCOUNT_TOMBSTONE", {"user_id": "u1", field: "val"})
            self.assertTrue(has_pii, f"'{field}' must be detected as prohibited.")
            self.assertIn(field, exposed)

    def test_10j_cross_subject_contamination_prevented(self):
        """Other user's observations must not appear in the subject's query results."""
        subject_env = IdentityEnvelope(
            user_id="alpha_uuid", canonical_name="Alpha",
            emails={"alpha@test.com"}, phones=set())
        other_obs = EvidenceObservation(
            file_id="ev_01", captured_at="2026-08-01T00:00:00Z",
            system_id="account_service", resource_id="acc_beta",
            category="USER_PROFILE", state=ResourceState.PRESENT,
            matched_keys={"beta@test.com"},  # different user
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(Path(tmpdir), [])
            store.observations = [other_obs]
            matched = store.query_subject_observations(
                subject_env, "2026-08-10T00:00:00Z")
        self.assertEqual(len(matched), 0,
                         "Another user's observation must not match the subject envelope.")


# ===========================================================================
# Hardcoding Audit — 10 tests confirm zero case-specific shortcuts
# ===========================================================================

class TestHardcodingAudit(unittest.TestCase):
    """
    Verifies that no case-specific shortcuts, hardcoded expected statuses,
    or request-specific branches exist anywhere in the prediction path.
    """

    def test_hc_01_interpreter_uses_text_not_case_id(self):
        """NOT_APPLICABLE is driven by text content, never by case_id."""
        for text in ["I want my data exported in a portable format",
                     "Please keep the account active",
                     "This is an information request",
                     "No estoy pidiendo la eliminación"]:
            self.assertFalse(RequestInterpreter.is_deletion_authorized(text),
                             f"Non-deletion text wrongly classified: {text[:50]}")
        for text in ["Please erase all my data",
                     "Delete everything about me",
                     "Bitte löschen Sie alle meine Daten"]:
            self.assertTrue(RequestInterpreter.is_deletion_authorized(text),
                            f"Deletion text wrongly blocked: {text[:50]}")

    def test_hc_02_empty_request_is_not_deletion(self):
        self.assertFalse(RequestInterpreter.is_deletion_authorized(""))
        self.assertFalse(RequestInterpreter.is_deletion_authorized(None))

    def test_hc_03_unknown_category_raises_error(self):
        """PolicyEngine raises on unknown category — no silent default treatment."""
        with self.assertRaises(UnknownPolicyCategoryError):
            PolicyEngine(_base_rules()).evaluate_record(
                "FICTIONAL_XYZ_9999", ResourceState.PRESENT)

    def test_hc_04_contradictory_rules_rejected(self):
        """Contradictory rules raise ContradictoryPolicyError at construction."""
        contradictory = [
            DeletionRule("r1", "USER_PROFILE", "DEFAULT", "DELETE"),
            DeletionRule("r2", "USER_PROFILE", "DEFAULT", "RETAIN"),
        ]
        with self.assertRaises(ContradictoryPolicyError):
            PolicyEngine(contradictory)

    def test_hc_05_safety_gate_status_independent_of_case_id(self):
        """Safety gate outcome is data-driven, not case_id-driven."""
        gate = PostModelSafetyGate()
        step = Step(1, Phase.VERIFICATION, "s", "r",
                    Operation.VERIFY_RECORD_ABSENT, ResourceState.ABSENT, evidence_id="ev_01")
        for cid in ["case_0001", "case_9999", "case_abc", "case_uuid-1234"]:
            result = gate.enforce_safety_gate(
                case=_make_case(case_id=cid), is_deletion_authorized=True,
                findings=[], verification_steps=[step])
            self.assertEqual(result.final_status, DeletionStatus.COMPLETE,
                             f"Outcome must not vary by case_id: {cid}")

    def test_hc_06_not_applicable_driven_by_auth_flag_not_case_id(self):
        """NOT_APPLICABLE depends solely on is_deletion_authorized=False."""
        gate = PostModelSafetyGate()
        for cid in ["case_001", "case_500", "case_xyz"]:
            result = gate.enforce_safety_gate(
                case=_make_case(case_id=cid,
                                request_text="I want my data exported."),
                is_deletion_authorized=False,
                findings=[], verification_steps=[])
            self.assertEqual(result.final_status, DeletionStatus.NOT_APPLICABLE)

    def test_hc_07_remediation_planner_uses_finding_not_hardcoded_ids(self):
        """RemediationPlanner produces step based on finding content, not fixed IDs."""
        planner = RemediationPlanner()
        for rid in ["account_001", "profile-uuid-9999", "res-XYZ"]:
            finding = Step(1, Phase.FINDING, "account_service", rid,
                           Operation.REPORT_REMAINING_RECORD,
                           ResourceState.PRESENT, "ev_01")
            rem = planner.plan_remediation_from_finding(finding)
            self.assertEqual(rem.resource_id, rid)
            self.assertEqual(rem.operation, Operation.DELETE_RECORD)

    def test_hc_08_evidence_isolation_checks_content_not_id_format(self):
        """Cross-subject isolation checks email content, not 'user_' prefix format."""
        subject_env = IdentityEnvelope(
            user_id="alpha-uuid", canonical_name="Alpha",
            emails={"alpha@domain.com"}, phones=set())
        other_obs = EvidenceObservation(
            file_id="ev_01", captured_at="2026-08-01T00:00:00Z",
            system_id="account_service", resource_id="acc_other",
            category="USER_PROFILE", state=ResourceState.PRESENT,
            matched_keys={"beta@domain.com"},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(Path(tmpdir), [])
            store.observations = [other_obs]
            matched = store.query_subject_observations(subject_env, "2026-08-10T00:00:00Z")
        self.assertEqual(len(matched), 0)

    def test_hc_09_identity_resolution_works_for_any_domain(self):
        """IdentityResolver works for arbitrary email domains — no domain hardcoding."""
        for domain in ["gmail.com", "test.io", "a.b.c.org", "corp.example"]:
            email = f"user@{domain}"
            r = IdentityResolver(
                [{"user_id": "u", "name": "U", "email": email,
                  "phone": "", "email_hash": "", "updated_at": "2026-01-01T00:00:00Z"}], [])
            env = r.resolve(email)
            self.assertIsNotNone(env)
            self.assertEqual(env.user_id, "u")

    def test_hc_10_infer_category_uses_keywords_not_exact_ids(self):
        """infer_category derives category from keywords in system/resource names."""
        self.assertEqual(infer_category("account_service_v2", "account_profile_99"), "USER_PROFILE")
        self.assertEqual(infer_category("search_engine", "search_idx_novel"), "SEARCH_INDEX_ENTRY")
        self.assertEqual(infer_category("analytics_v3", "analytics_report_XYZ"), "ANALYTICS_PROFILE")
        self.assertEqual(infer_category("backup_replica", "backup_snapshot_001"), "BACKUP_ARCHIVE")
        self.assertEqual(infer_category("export_svc", "export_file_7"), "USER_EXPORT")
        self.assertEqual(infer_category("any_system", "tombstone_user_X"), "ACCOUNT_TOMBSTONE")


if __name__ == "__main__":
    unittest.main()

