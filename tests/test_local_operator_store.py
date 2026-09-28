"""Persistence and lockout contracts for deployment-managed local operators."""

from __future__ import annotations

import sqlite3
import os
import tempfile
import unittest
from pathlib import Path

from argon2 import PasswordHasher
from argon2.low_level import Type

from narrowcti.adapters.persistence.local.operator_store import (
    FirstOperatorMustBeAdmin,
    LastEnabledAdmin,
    LocalOperatorStore,
    OperatorStoreError,
)
from narrowcti.application.identity.passwords import PasswordService


class LocalOperatorStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "new-auth-directory" / "auth.db"
        self.store = LocalOperatorStore(self.path)
        self.passwords = PasswordService(PasswordHasher(
            time_cost=1, memory_cost=8, parallelism=1, hash_len=16, salt_len=8, type=Type.ID
        ))

    def test_schema_is_versioned_and_initialization_is_idempotent(self):
        LocalOperatorStore(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(1, connection.execute("PRAGMA user_version").fetchone()[0])
        finally:
            connection.close()
        self.assertFalse(self.store.has_operators())

    def test_future_schema_fails_closed(self):
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA user_version = 99")
        finally:
            connection.close()
        with self.assertRaises(OperatorStoreError):
            LocalOperatorStore(self.path)

    @unittest.skipIf(os.name == "nt", "POSIX file modes are not portable to Windows")
    def test_auth_database_and_parent_directory_use_restrictive_modes(self):
        self.assertEqual(0o700, self.path.parent.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.path.stat().st_mode & 0o777)

    def test_first_account_must_be_admin_and_last_enabled_admin_is_protected(self):
        password_hash = self.passwords.hash_password("synthetic admin passphrase")
        with self.assertRaises(FirstOperatorMustBeAdmin):
            self.store.create_operator("first", password_hash, ["reader"])
        admin = self.store.create_operator("RootAdmin", password_hash, ["admin"])
        self.assertEqual("rootadmin", admin.username)
        with self.assertRaises(LastEnabledAdmin):
            self.store.set_enabled(admin.operator_id, False)
        with self.assertRaises(LastEnabledAdmin):
            self.store.set_roles(admin.operator_id, ["reader"])

    def test_identity_is_stable_and_password_hash_is_never_in_repr_or_public_projection(self):
        password = "synthetic identity passphrase"
        password_hash = self.passwords.hash_password(password)
        self.store.create_operator(
            "admin", self.passwords.hash_password("synthetic admin passphrase"), ["admin"]
        )
        record = self.store.create_operator("analyst", password_hash, ["reader"])
        fetched = self.store.get_by_username("ANALYST")
        self.assertEqual(record.operator_id, fetched.operator_id)
        self.assertNotIn(password_hash, repr(record))
        self.assertNotIn(password_hash, repr(fetched.to_public_dict()))
        self.assertNotIn(password, repr(fetched.to_public_dict()))
        self.assertEqual(1, fetched.auth_revision)

    def test_password_and_role_changes_increment_auth_revision(self):
        record = self.store.create_operator(
            "admin", self.passwords.hash_password("synthetic change passphrase"), ["admin"]
        )
        self.store.create_operator(
            "admin2", self.passwords.hash_password("synthetic second admin passphrase"), ["admin"]
        )
        changed_password = self.store.set_password_hash(
            record.operator_id, self.passwords.hash_password("synthetic replacement passphrase")
        )
        self.assertEqual(record.auth_revision + 1, changed_password.auth_revision)
        changed_roles = self.store.set_roles(record.operator_id, ["reader", "reviewer"])
        self.assertEqual(changed_password.auth_revision + 1, changed_roles.auth_revision)

    def test_password_change_uses_compare_and_swap_and_revokes_sessions(self):
        record = self.store.create_operator(
            "admin", self.passwords.hash_password("synthetic initial passphrase"), ["admin"]
        )
        new_hash = self.passwords.hash_password("synthetic changed passphrase")
        self.assertFalse(self.store.change_password_hash(record.operator_id, "stale-hash", new_hash))
        self.assertTrue(self.store.change_password_hash(record.operator_id, record.password_hash, new_hash))
        self.assertEqual(record.auth_revision + 1, self.store.get_by_id(record.operator_id).auth_revision)

    def test_username_is_bounded_ascii_and_passwords_are_not_trimmed_by_store(self):
        with self.assertRaises(ValueError):
            self.store.create_operator(" name ", self.passwords.hash_password("synthetic passphrase"), ["admin"])
        with self.assertRaises(ValueError):
            self.store.create_operator("føø", self.passwords.hash_password("synthetic passphrase"), ["admin"])


if __name__ == "__main__":
    unittest.main()
