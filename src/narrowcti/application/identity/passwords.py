"""Bounded Argon2id password hashing and local operator authentication."""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

from narrowcti.domain.security.operators import OperatorRecord
from narrowcti.ports.operator_store import OperatorStore

MIN_PASSWORD_CHARACTERS = 15
MAX_PASSWORD_BYTES = 1024
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST_KIB = 19 * 1024
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_LENGTH = 16


class PasswordPolicyError(ValueError):
    pass


class PasswordService:
    """Password hashing policy; tests may inject a separate test hasher."""

    def __init__(self, hasher: PasswordHasher | None = None):
        self.hasher = hasher or PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LENGTH,
            salt_len=ARGON2_SALT_LENGTH,
            type=Type.ID,
        )
        self._dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))

    @staticmethod
    def validate_password(password: str) -> None:
        if not isinstance(password, str):
            raise PasswordPolicyError("password must be text")
        if len(password) < MIN_PASSWORD_CHARACTERS:
            raise PasswordPolicyError(
                f"password must contain at least {MIN_PASSWORD_CHARACTERS} characters"
            )
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise PasswordPolicyError(f"password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes")

    def hash_password(self, password: str) -> str:
        self.validate_password(password)
        return self.hasher.hash(password)

    def verify_hash(self, password_hash: str, password: str) -> bool:
        return self.verify_hash_result(password_hash, password) is True

    def verify_hash_result(self, password_hash: str, password: str) -> bool | None:
        """Return ``None`` for malformed hashes, distinct from a wrong password."""
        try:
            self.hasher.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError, ValueError, TypeError):
            return None

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self.hasher.check_needs_rehash(password_hash)
        except (InvalidHashError, VerificationError, ValueError, TypeError):
            return False


class LocalOperatorAuthenticator:
    """Authenticate operators without username enumeration or stale role snapshots."""

    def __init__(self, store: OperatorStore, passwords: PasswordService | None = None):
        self.store = store
        self.passwords = passwords or PasswordService()

    def authenticate(self, username: str, password: str) -> OperatorRecord | None:
        try:
            self.passwords.validate_password(password)
        except PasswordPolicyError:
            return None
        record = self.store.get_by_username(username)
        encoded = record.password_hash if record else self.passwords._dummy_hash
        verified = self.passwords.verify_hash_result(encoded, password)
        if verified is None and record is not None:
            # A corrupt stored PHC string must not turn into a fast user-enumeration path.
            self.passwords.verify_hash(self.passwords._dummy_hash, password)
            return None
        if not record or not record.enabled or not verified:
            return None
        if self.passwords.needs_rehash(record.password_hash):
            replacement = self.passwords.hash_password(password)
            self.store.replace_password_hash(record.operator_id, record.password_hash, replacement)
        current = self.store.get_by_id(record.operator_id)
        if (
            current is None
            or not current.enabled
            or current.auth_revision != record.auth_revision
        ):
            return None
        return current

    def change_password(self, operator_id: str, current_password: str, new_password: str) -> bool:
        self.passwords.validate_password(new_password)
        try:
            self.passwords.validate_password(current_password)
        except PasswordPolicyError:
            return False
        record = self.store.get_by_id(operator_id)
        if not record or not record.enabled:
            return False
        if not self.passwords.verify_hash(record.password_hash, current_password):
            return False
        return self.store.change_password_hash(
            operator_id,
            record.password_hash,
            self.passwords.hash_password(new_password),
        )


__all__ = [
    "ARGON2_HASH_LENGTH", "ARGON2_MEMORY_COST_KIB", "ARGON2_PARALLELISM",
    "ARGON2_SALT_LENGTH", "ARGON2_TIME_COST", "MAX_PASSWORD_BYTES",
    "MIN_PASSWORD_CHARACTERS", "LocalOperatorAuthenticator", "PasswordPolicyError",
    "PasswordService",
]
