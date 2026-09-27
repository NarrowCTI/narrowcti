"""Shared SQLite runtime-store owner for jobs and process coordination.

Business state remains in its historical JSON/JSONL files.  This store contains
only coordination metadata and bounded runtime jobs.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager


SCHEMA_VERSION = 1
DEFAULT_BUSY_TIMEOUT_MS = 5000
JOURNAL_MODE = "DELETE"


class SQLiteRuntimeStore:
    """Own connection/bootstrap policy for the local runtime database."""

    def __init__(self, path: str, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS):
        if not path:
            raise ValueError("runtime database path is required")
        self.path = os.path.abspath(os.fspath(path))
        self.busy_timeout_ms = int(busy_timeout_ms)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=max(self.busy_timeout_ms / 1000.0, 0.1),
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys=ON")
        # Do not assume WAL support on arbitrary mounts.  DELETE is explicit.
        # Consume the result row so Windows releases the journal-mode cursor
        # before the connection is closed by the transaction context.
        connection.execute(f"PRAGMA journal_mode={JOURNAL_MODE}").fetchone()
        return connection

    @contextmanager
    def transaction(self, *, immediate: bool = False):
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self):
        with self.transaction(immediate=True) as connection:
            statements = (
                """CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    job_type TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'succeeded', 'failed')),
                    created_at TEXT NOT NULL,
                    claimed_at TEXT,
                    claim_owner TEXT,
                    lease_until REAL,
                    started_at TEXT,
                    finished_at TEXT,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    result_json TEXT,
                    error TEXT,
                    UNIQUE(job_type, idempotency_key)
                )""",
                """CREATE INDEX IF NOT EXISTS jobs_claim_index
                    ON jobs(status, lease_until, created_at)""",
                """CREATE TABLE IF NOT EXISTS worker_leases (
                    role TEXT PRIMARY KEY,
                    owner_token TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    lease_until REAL NOT NULL,
                    last_heartbeat TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS mutation_coordination (
                    scope TEXT PRIMARY KEY,
                    owner_token TEXT NOT NULL,
                    lease_until REAL NOT NULL
                )""",
            )
            for statement in statements:
                connection.execute(statement)
            connection.execute(
                "INSERT OR REPLACE INTO schema_metadata(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


__all__ = ["DEFAULT_BUSY_TIMEOUT_MS", "JOURNAL_MODE", "SCHEMA_VERSION", "SQLiteRuntimeStore"]
