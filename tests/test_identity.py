"""Unit test suite for the identity resolution module.
Covers:
1. Exact matches on current email snapshot
2. Exact matches on historical email changes via user_audit_log
3. Full identity envelope construction (emails, phones, hashes)
4. Identifier normalization (casing, whitespace, international phones)
5. Ambiguous matches and collision detection across users
6. Prevention of false matches based on common names
7. Handling of missing or malformed identifier inputs
8. Deterministic handling of previously unseen/unregistered users
9. Resolution validation across all sample cases in sample_deletion_requests.csv
"""
import unittest
from pathlib import Path

from code.config import Config
from code.core.loader import DataLoader
from code.core.identity import (
    IdentityResolver, normalize_email, normalize_phone, normalize_hash
)
from code.models import MatchType, MatchConfidence
from code.core.errors import InvalidDataFormatError

class TestIdentityResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.identities = DataLoader.load_user_identities(cls.config.user_identities_path)
        cls.audit_logs = DataLoader.load_user_audit_log(cls.config.user_audit_log_path)
        cls.resolver = IdentityResolver(cls.identities, cls.audit_logs)

    # =========================================================================
    # 1. Current Email Resolution
    # =========================================================================
    def test_resolve_current_email_exact(self):
        """Resolves current email directly from user_identities.csv."""
        # user_43 current email: l.fontaine46@yahoo.com
        res = self.resolver.resolve_identity("l.fontaine46@yahoo.com")
        self.assertEqual(res.match_type, MatchType.EXACT_CURRENT_EMAIL)
        self.assertEqual(res.confidence, MatchConfidence.CONFIRMED)
        self.assertEqual(res.primary_user_id, "user_43")
        self.assertFalse(res.is_ambiguous)
        self.assertTrue(res.is_registered)

        env = res.envelope
        self.assertIsNotNone(env)
        self.assertEqual(env.user_id, "user_43")
        self.assertIn("l.fontaine46@yahoo.com", env.emails)
        self.assertGreater(len(env.email_hashes), 0)
        self.assertGreater(len(res.evidence_trail), 0)
        self.assertEqual(res.evidence_trail[0].source_file, "user_identities.csv")

    # =========================================================================
    # 2. Historical Email Changes
    # =========================================================================
    def test_resolve_historical_email_change(self):
        """Resolves historical email changed in user_audit_log.csv."""
        # case_10: nadia.ionescu@yahoo.com was changed in audit log
        res = self.resolver.resolve_identity("nadia.ionescu@yahoo.com")
        self.assertIn(res.match_type, [MatchType.EXACT_HISTORICAL_EMAIL, MatchType.EXACT_CURRENT_EMAIL])
        self.assertEqual(res.confidence, MatchConfidence.CONFIRMED)
        self.assertEqual(res.primary_user_id, "user_10")

        env = res.envelope
        self.assertIsNotNone(env)
        self.assertEqual(env.user_id, "user_10")
        self.assertIn("nadia.ionescu@yahoo.com", env.emails)

        # Confirm evidence trail cites user_audit_log or user_identities
        sources = {item.source_file for item in res.evidence_trail}
        self.assertTrue(any("audit" in s or "identities" in s for s in sources))

    # =========================================================================
    # 3. Identifier Normalization
    # =========================================================================
    def test_email_normalization(self):
        """Tests email normalization trimming and case-insensitivity."""
        self.assertEqual(normalize_email("  L.Fontaine46@Yahoo.COM  "), "l.fontaine46@yahoo.com")
        self.assertEqual(normalize_email("not-an-email"), "")
        self.assertEqual(normalize_email(""), "")

        # Resolving uppercase email should resolve to the exact same user
        res = self.resolver.resolve_identity("  L.Fontaine46@Yahoo.COM  ")
        self.assertEqual(res.primary_user_id, "user_43")

    def test_phone_normalization(self):
        """Tests phone number normalization."""
        self.assertEqual(normalize_phone("+33 6 24 34 80 16"), "+33624348016")
        self.assertEqual(normalize_phone("(555) 123-4567"), "5551234567")
        self.assertEqual(normalize_phone("invalid"), "")

    def test_hash_normalization(self):
        """Tests SHA-256 hash validation and normalization."""
        valid_hash = "4f4b9c98a05a2dad20e52313cce7809d18c3da544754dcd46d728b0173174b26"
        self.assertEqual(normalize_hash(valid_hash.upper()), valid_hash)
        self.assertEqual(normalize_hash("too_short"), "")
        self.assertEqual(normalize_hash("not_hex_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), "")

    # =========================================================================
    # 4. Ambiguous Matches & Collision Detection
    # =========================================================================
    def test_detect_identity_collision(self):
        """Detects and flags when multiple users claim the same email."""
        colliding_identities = [
            {"user_id": "user_A", "name": "Alice A", "email": "shared@corp.com", "phone": "+1 555 111", "email_hash": "a"*64, "updated_at": "2026-09-01T10:00:00Z"},
            {"user_id": "user_B", "name": "Bob B", "email": "other@corp.com", "phone": "+1 555 222", "email_hash": "b"*64, "updated_at": "2026-09-01T10:00:00Z"}
        ]
        colliding_audit = [
            {"audit_id": "aud_99", "user_id": "user_B", "event_time": "2026-08-01T10:00:00Z", "field_name": "email", "old_value": "shared@corp.com", "new_value": "other@corp.com"}
        ]
        collision_resolver = IdentityResolver(colliding_identities, colliding_audit)

        res = collision_resolver.resolve_identity("shared@corp.com")
        self.assertEqual(res.match_type, MatchType.AMBIGUOUS_COLLISION)
        self.assertEqual(res.confidence, MatchConfidence.AMBIGUOUS)
        self.assertTrue(res.is_ambiguous)
        self.assertIsNone(res.primary_user_id)
        self.assertIsNone(res.envelope)
        self.assertIn("user_a", res.collisions)
        self.assertIn("user_b", res.collisions)

    # =========================================================================
    # 5. Prevention of False Matches by Name
    # =========================================================================
    def test_no_false_match_based_on_name(self):
        """Identical names across distinct users must NEVER cause cross-identity merging."""
        same_name_identities = [
            {"user_id": "user_101", "name": "David Miller", "email": "david.m1@test.com", "phone": "+1 555 001", "email_hash": "1"*64, "updated_at": "2026-09-01T10:00:00Z"},
            {"user_id": "user_102", "name": "David Miller", "email": "david.m2@test.com", "phone": "+1 555 002", "email_hash": "2"*64, "updated_at": "2026-09-01T10:00:00Z"},
        ]
        resolver = IdentityResolver(same_name_identities, [])

        res1 = resolver.resolve_identity("david.m1@test.com")
        self.assertEqual(res1.primary_user_id, "user_101")
        self.assertNotIn("david.m2@test.com", res1.envelope.emails)
        self.assertNotIn("+1 555 002", res1.envelope.phones)

        res2 = resolver.resolve_identity("david.m2@test.com")
        self.assertEqual(res2.primary_user_id, "user_102")
        self.assertNotIn("david.m1@test.com", res2.envelope.emails)
        self.assertNotIn("+1 555 001", res2.envelope.phones)

    # =========================================================================
    # 6. Missing or Malformed Identifiers
    # =========================================================================
    def test_missing_or_empty_email_raises_error(self):
        """Resolving missing or empty email strings raises InvalidDataFormatError."""
        with self.assertRaises(InvalidDataFormatError):
            self.resolver.resolve_identity("")
        with self.assertRaises(InvalidDataFormatError):
            self.resolver.resolve_identity("   ")
        with self.assertRaises(InvalidDataFormatError):
            self.resolver.resolve_identity(None)

    # =========================================================================
    # 7. Previously Unseen / Unregistered Users
    # =========================================================================
    def test_unseen_user_resolution(self):
        """Unseen email returns unregistered result with fallback envelope without guessing."""
        unseen_email = "completely.unseen.contact.2026@external.io"
        res = self.resolver.resolve_identity(unseen_email)
        self.assertEqual(res.match_type, MatchType.UNRESOLVED)
        self.assertEqual(res.confidence, MatchConfidence.UNREGISTERED)
        self.assertFalse(res.is_registered)
        self.assertFalse(res.is_ambiguous)
        self.assertIsNone(res.primary_user_id)

        env = res.envelope
        self.assertIsNotNone(env)
        self.assertTrue(env.user_id.startswith("unregistered_"))
        self.assertIn(unseen_email, env.emails)
        self.assertGreater(len(env.email_hashes), 0)

    # =========================================================================
    # 8. Real Repository Validation (All 32 Sample Cases)
    # =========================================================================
    def test_resolve_all_sample_cases(self):
        """Ensures all 32 sample request emails resolve deterministically."""
        sample_cases = DataLoader.load_deletion_cases(self.config.sample_requests_path)
        self.assertEqual(len(sample_cases), 32)

        for c in sample_cases:
            res = self.resolver.resolve_identity(c.email)
            self.assertIsNotNone(res)
            # Must either be confirmed registered or unregistered
            self.assertIn(res.confidence, [MatchConfidence.CONFIRMED, MatchConfidence.UNREGISTERED])
            env = self.resolver.resolve(c.email)
            self.assertIsNotNone(env)
            self.assertIn(c.email.strip().lower(), env.emails)

if __name__ == "__main__":
    unittest.main()
