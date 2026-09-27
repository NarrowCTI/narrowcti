"""Cross-process critical sections for existing JSON/JSONL writers."""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager

from .sqlite_runtime_store import SQLiteRuntimeStore


class SQLiteProcessCoordinationRepository:
    def __init__(self, store: SQLiteRuntimeStore):
        self.store = store

    def acquire(self, scope: str, owner_token: str, timeout_seconds: float = 30.0, lease_seconds: int = 120) -> bool:
        deadline = time.monotonic() + max(float(timeout_seconds), 0.0)
        while True:
            try:
                now_epoch = time.time()
                until = now_epoch + max(int(lease_seconds), 1)
                with self.store.transaction(immediate=True) as connection:
                    row = connection.execute(
                        "SELECT * FROM mutation_coordination WHERE scope=?", (scope,)
                    ).fetchone()
                    if row is None or float(row["lease_until"]) <= now_epoch or row["owner_token"] == owner_token:
                        connection.execute(
                            """
                            INSERT INTO mutation_coordination(scope, owner_token, lease_until)
                            VALUES (?, ?, ?)
                            ON CONFLICT(scope) DO UPDATE SET owner_token=excluded.owner_token,
                                lease_until=excluded.lease_until
                            """,
                            (scope, owner_token, until),
                        )
                        return True
            except Exception:
                if time.monotonic() >= deadline:
                    raise
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def release(self, scope: str, owner_token: str) -> bool:
        with self.store.transaction(immediate=True) as connection:
            deleted = connection.execute(
                "DELETE FROM mutation_coordination WHERE scope=? AND owner_token=?",
                (scope, owner_token),
            )
        return deleted.rowcount == 1

    @contextmanager
    def exclusive(self, scope: str, owner_token: str | None = None, timeout_seconds: float = 30.0, lease_seconds: int = 120):
        owner_token = owner_token or str(uuid.uuid4())
        if not self.acquire(scope, owner_token, timeout_seconds, lease_seconds):
            raise TimeoutError(f"timed out waiting for coordination scope: {scope}")
        try:
            yield owner_token
        finally:
            self.release(scope, owner_token)


def runtime_db_for_path(path: str) -> str:
    import os

    configured = os.environ.get("NARROWCTI_RUNTIME_DB", "").strip()
    if configured:
        return configured
    return os.path.join(os.path.dirname(os.path.abspath(path)) or ".", "runtime.db")


def coordination_for_path(path: str) -> SQLiteProcessCoordinationRepository:
    return SQLiteProcessCoordinationRepository(SQLiteRuntimeStore(runtime_db_for_path(path)))


__all__ = ["SQLiteProcessCoordinationRepository", "coordination_for_path", "runtime_db_for_path"]
