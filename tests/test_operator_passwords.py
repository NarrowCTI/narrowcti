"""Argon2id and local-operator authentication behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from argon2 import PasswordHasher
from argon2.low_level import Type

from narrowcti.adapters.persistence.local.operator_store import LocalOperatorStore
from narrowcti.application.identity.passwords import (
    LocalOperatorAuthenticator,
    PasswordPolicyError,
    PasswordService,
)
from narrowcti.api.review.auth import ReviewPrincipal
from narrowcti.domain.security.identity import LocalOperatorPrincipal


def _service():
    return PasswordService(PasswordHasher(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=16, salt_len=8, type=Type.ID
    ))


class LocalOperatorPasswordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = LocalOperatorStore(Path(self.temp.name) / "auth.db")
        self.passwords = _service()
        self.store.create_operator(
            "admin", self.passwords.hash_password("synthetic admin passphrase"), ["admin"]
        )
        self.record = self.store.create_operator(
            "reader", self.passwords.hash_password("synthetic reader passphrase"), ["reader"]
        )
        self.auth = LocalOperatorAuthenticator(self.store, self.passwords)

    def test_password_policy_bounds_without_composition_rules_or_trimming(self):
        with self.assertRaises(PasswordPolicyError):
            self.passwords.hash_password("short")
        with self.assertRaises(PasswordPolicyError):
            self.passwords.hash_password("x" * 1025)
        password = "  spaces are allowed  "
        encoded = self.passwords.hash_password(password)
        self.assertTrue(self.passwords.verify_hash(encoded, password))
        self.assertFalse(self.passwords.verify_hash(encoded, password.strip()))
        self.assertNotIn(password, repr(self.passwords))

    def test_authentication_is_generic_for_unknown_wrong_and_disabled_accounts(self):
        self.assertIsNotNone(self.auth.authenticate("READER", "synthetic reader passphrase"))
        self.assertIsNone(self.auth.authenticate("missing", "synthetic reader passphrase"))
        self.assertIsNone(self.auth.authenticate("reader", "wrong synthetic passphrase"))
        self.store.set_enabled(self.record.operator_id, False)
        self.assertIsNone(self.auth.authenticate("reader", "synthetic reader passphrase"))

    def test_bearer_and_browser_principals_share_permission_semantics(self):
        bearer = ReviewPrincipal("analyst", frozenset({"reader", "reviewer"}), "api-key")
        local = LocalOperatorPrincipal("operator-id", "analyst", frozenset({"reader", "reviewer"}), 1)
        for permission in ("review:read", "source:explore", "review:decide", "export:preview"):
            self.assertEqual(bearer.has_permission(permission), local.has_permission(permission))

    def test_password_change_invalidates_revision_and_old_password(self):
        self.assertTrue(self.auth.change_password(
            self.record.operator_id,
            "synthetic reader passphrase",
            "synthetic replacement passphrase",
        ))
        self.assertIsNone(self.auth.authenticate("reader", "synthetic reader passphrase"))
        changed = self.auth.authenticate("reader", "synthetic replacement passphrase")
        self.assertIsNotNone(changed)
        self.assertGreater(changed.auth_revision, self.record.auth_revision)

    def test_parameter_rehash_does_not_revoke_operator_sessions(self):
        stronger = PasswordService(PasswordHasher(
            time_cost=2, memory_cost=16, parallelism=1, hash_len=16, salt_len=8, type=Type.ID
        ))
        authenticated = LocalOperatorAuthenticator(self.store, stronger).authenticate(
            "reader", "synthetic reader passphrase"
        )
        self.assertIsNotNone(authenticated)
        self.assertEqual(self.record.auth_revision, authenticated.auth_revision)
        updated = self.store.get_by_id(self.record.operator_id)
        self.assertEqual(self.record.auth_revision, updated.auth_revision)
        self.assertFalse(stronger.needs_rehash(updated.password_hash))

    def test_malformed_stored_hash_fails_closed_without_raising(self):
        with self.store._connection() as connection:
            connection.execute("UPDATE operators SET password_hash = 'bad' WHERE operator_id = ?", (self.record.operator_id,))
        self.assertIsNone(self.auth.authenticate("reader", "synthetic reader passphrase"))


if __name__ == "__main__":
    unittest.main()
