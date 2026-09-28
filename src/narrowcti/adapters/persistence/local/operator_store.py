"""SQLite repository for deployment-managed Community Web operators."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from narrowcti.domain.security.identity import VALID_ROLES
from narrowcti.domain.security.operators import OperatorRecord

SCHEMA_VERSION = 1
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PASSWORD_HASH_PATTERN = re.compile(r"^\$argon2id\$v=19\$[^\s]{20,512}$")


class OperatorStoreError(RuntimeError):
    """Safe operator-store failure; intentionally excludes database paths/data."""


class DuplicateUsername(OperatorStoreError):
    pass


class FirstOperatorMustBeAdmin(OperatorStoreError):
    pass


class LastEnabledAdmin(OperatorStoreError):
    pass


class OperatorNotFound(OperatorStoreError):
    pass


def normalize_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("username must be 1–64 ASCII letters, digits, dot, underscore or hyphen")
    return username.lower()


def normalize_roles(roles: Iterable[str]) -> frozenset[str]:
    normalized = frozenset(str(role).lower() for role in roles)
    if not normalized or normalized - VALID_ROLES:
        raise ValueError("at least one known operator role is required")
    return normalized


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class LocalOperatorStore:
    """Versioned SQLite operator store, independent from the runtime job DB."""

    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_seconds: float = 5.0):
        if not path:
            raise ValueError("operator database path is required")
        self.path = Path(path)
        self.busy_timeout_seconds = max(0.1, float(busy_timeout_seconds))
        self._initialize()

    def _initialize(self) -> None:
        try:
            parent_existed = self.path.parent.exists()
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt" and not parent_existed:
                os.chmod(self.path.parent, 0o700)
            connection = sqlite3.connect(self.path, timeout=self.busy_timeout_seconds, isolation_level=None)
            try:
                connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}")
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > SCHEMA_VERSION:
                    raise OperatorStoreError("unsupported future operator database schema")
                connection.execute("PRAGMA journal_mode = WAL")
                if version == 0:
                    existing = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                    if existing:
                        raise OperatorStoreError("unversioned operator database is not empty")
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        """CREATE TABLE operators (
                            operator_id TEXT PRIMARY KEY,
                            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                            password_hash TEXT NOT NULL,
                            roles_json TEXT NOT NULL,
                            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                            auth_revision INTEGER NOT NULL CHECK (auth_revision >= 1),
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            password_changed_at TEXT NOT NULL
                        )"""
                    )
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    connection.commit()
                self._validate_schema(connection)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        except OperatorStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise OperatorStoreError("operator database is unavailable") from None

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            raise OperatorStoreError("unsupported operator database schema")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(operators)")}
        required = {
            "operator_id", "username", "password_hash", "roles_json", "enabled",
            "auth_revision", "created_at", "updated_at", "password_changed_at",
        }
        if columns != required:
            raise OperatorStoreError("operator database schema is invalid")

    @contextmanager
    def _connection(self):
        connection = None
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.busy_timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}")
            self._validate_schema(connection)
        except OperatorStoreError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error:
            if connection is not None:
                connection.close()
            raise OperatorStoreError("operator database is unavailable") from None
        try:
            yield connection
        except OperatorStoreError:
            raise
        except sqlite3.Error:
            raise OperatorStoreError("operator database is unavailable") from None
        finally:
            connection.close()

    @staticmethod
    def _record(row: sqlite3.Row | None) -> OperatorRecord | None:
        if row is None:
            return None
        try:
            roles = json.loads(row["roles_json"])
            if not isinstance(roles, list):
                raise ValueError
            normalized_roles = normalize_roles(roles)
            return OperatorRecord(
                operator_id=str(row["operator_id"]),
                username=normalize_username(str(row["username"])),
                password_hash=str(row["password_hash"]),
                roles=normalized_roles,
                enabled=bool(row["enabled"]),
                auth_revision=int(row["auth_revision"]),
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
                password_changed_at=str(row["password_changed_at"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise OperatorStoreError("operator record is invalid") from None

    @staticmethod
    def _validate_hash(password_hash: str) -> str:
        if not isinstance(password_hash, str) or not PASSWORD_HASH_PATTERN.fullmatch(password_hash):
            raise ValueError("a valid Argon2id password hash is required")
        return password_hash

    def has_operators(self) -> bool:
        with self._connection() as connection:
            return connection.execute("SELECT 1 FROM operators LIMIT 1").fetchone() is not None

    def get_by_id(self, operator_id: str) -> OperatorRecord | None:
        with self._connection() as connection:
            return self._record(connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone())

    def get_by_username(self, username: str) -> OperatorRecord | None:
        try:
            normalized = normalize_username(username)
        except ValueError:
            return None
        with self._connection() as connection:
            return self._record(connection.execute(
                "SELECT * FROM operators WHERE username = ?", (normalized,)
            ).fetchone())

    def list_operators(self) -> tuple[OperatorRecord, ...]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM operators ORDER BY username").fetchall()
        return tuple(self._record(row) for row in rows)

    def create_operator(self, username: str, password_hash: str, roles: Iterable[str]) -> OperatorRecord:
        normalized_username = normalize_username(username)
        normalized_hash = self._validate_hash(password_hash)
        normalized_roles = normalize_roles(roles)
        now = _now()
        operator_id = uuid.uuid4().hex
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute("SELECT COUNT(*) FROM operators").fetchone()[0])
            if count == 0 and "admin" not in normalized_roles:
                raise FirstOperatorMustBeAdmin("the first local operator must include the admin role")
            try:
                connection.execute(
                    """INSERT INTO operators
                    (operator_id, username, password_hash, roles_json, enabled, auth_revision,
                     created_at, updated_at, password_changed_at)
                    VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?)""",
                    (operator_id, normalized_username, normalized_hash,
                     json.dumps(sorted(normalized_roles), separators=(",", ":")), now, now, now),
                )
            except sqlite3.IntegrityError as exc:
                if "username" in str(exc).lower():
                    raise DuplicateUsername("an operator with that username already exists") from None
                raise OperatorStoreError("operator could not be created") from None
            row = connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone()
            connection.commit()
        return self._record(row)

    def replace_password_hash(self, operator_id: str, expected_hash: str, new_hash: str) -> bool:
        self._validate_hash(new_hash)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE operators SET password_hash = ?, updated_at = ? "
                "WHERE operator_id = ? AND password_hash = ?",
                (new_hash, _now(), operator_id, expected_hash),
            )
            connection.commit()
            return cursor.rowcount == 1

    def change_password_hash(self, operator_id: str, expected_hash: str, new_hash: str) -> bool:
        """Change only the hash that was verified and revoke active sessions."""
        self._validate_hash(new_hash)
        now = _now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE operators SET password_hash = ?, auth_revision = auth_revision + 1, "
                "updated_at = ?, password_changed_at = ? "
                "WHERE operator_id = ? AND password_hash = ? AND enabled = 1",
                (new_hash, now, now, operator_id, expected_hash),
            )
            connection.commit()
            return cursor.rowcount == 1

    def set_password_hash(self, operator_id: str, password_hash: str) -> OperatorRecord:
        self._validate_hash(password_hash)
        now = _now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE operators SET password_hash = ?, auth_revision = auth_revision + 1, "
                "updated_at = ?, password_changed_at = ? WHERE operator_id = ?",
                (password_hash, now, now, operator_id),
            )
            if cursor.rowcount != 1:
                raise OperatorNotFound("operator was not found")
            row = connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone()
            connection.commit()
        return self._record(row)

    def set_roles(self, operator_id: str, roles: Iterable[str]) -> OperatorRecord:
        normalized_roles = normalize_roles(roles)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone()
            current = self._record(row)
            if current is None:
                raise OperatorNotFound("operator was not found")
            if current.roles == normalized_roles:
                connection.commit()
                return current
            if current.enabled and "admin" in current.roles and "admin" not in normalized_roles:
                admins = int(connection.execute(
                    "SELECT COUNT(*) FROM operators WHERE enabled = 1 "
                    "AND roles_json LIKE '%\"admin\"%'"
                ).fetchone()[0])
                if admins <= 1:
                    raise LastEnabledAdmin("cannot remove admin from the last enabled administrator")
            connection.execute(
                "UPDATE operators SET roles_json = ?, auth_revision = auth_revision + 1, updated_at = ? "
                "WHERE operator_id = ?",
                (json.dumps(sorted(normalized_roles), separators=(",", ":")), _now(), operator_id),
            )
            updated = self._record(connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone())
            connection.commit()
        return updated

    def set_enabled(self, operator_id: str, enabled: bool) -> OperatorRecord:
        enabled = bool(enabled)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone()
            current = self._record(row)
            if current is None:
                raise OperatorNotFound("operator was not found")
            if current.enabled == enabled:
                connection.commit()
                return current
            if not enabled and "admin" in current.roles:
                admins = int(connection.execute(
                    "SELECT COUNT(*) FROM operators WHERE enabled = 1 "
                    "AND roles_json LIKE '%\"admin\"%'"
                ).fetchone()[0])
                if admins <= 1:
                    raise LastEnabledAdmin("cannot disable the last enabled administrator")
            connection.execute(
                "UPDATE operators SET enabled = ?, auth_revision = auth_revision + 1, updated_at = ? "
                "WHERE operator_id = ?",
                (int(enabled), _now(), operator_id),
            )
            updated = self._record(connection.execute(
                "SELECT * FROM operators WHERE operator_id = ?", (operator_id,)
            ).fetchone())
            connection.commit()
        return updated


__all__ = [
    "DuplicateUsername", "FirstOperatorMustBeAdmin", "LastEnabledAdmin",
    "LocalOperatorStore", "OperatorNotFound", "OperatorStoreError",
    "normalize_roles", "normalize_username",
]
