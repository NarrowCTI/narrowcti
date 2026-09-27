"""Process-safe Worker instance lease backed by the runtime store."""

from __future__ import annotations

import time
import uuid

from .job_repository import utc_now
from .sqlite_runtime_store import SQLiteRuntimeStore


WORKER_LEASE_HELD_EXIT_CODE = 75


class SQLiteWorkerLeaseRepository:
    def __init__(self, store: SQLiteRuntimeStore):
        self.store = store

    def acquire(self, role: str, owner_token: str, lease_seconds: int = 60) -> bool:
        if not role or not owner_token:
            raise ValueError("role and owner token are required")
        now_epoch = time.time()
        now = utc_now()
        until = now_epoch + max(int(lease_seconds), 1)
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute("SELECT * FROM worker_leases WHERE role=?", (role,)).fetchone()
            if row and row["owner_token"] != owner_token and float(row["lease_until"]) > now_epoch:
                return False
            connection.execute(
                """
                INSERT INTO worker_leases(role, owner_token, acquired_at, lease_until, last_heartbeat)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(role) DO UPDATE SET owner_token=excluded.owner_token,
                    acquired_at=excluded.acquired_at, lease_until=excluded.lease_until,
                    last_heartbeat=excluded.last_heartbeat
                """,
                (role, owner_token, now, until, now),
            )
        return True

    def renew(self, role: str, owner_token: str, lease_seconds: int = 60) -> bool:
        now = utc_now()
        until = time.time() + max(int(lease_seconds), 1)
        with self.store.transaction(immediate=True) as connection:
            updated = connection.execute(
                "UPDATE worker_leases SET lease_until=?, last_heartbeat=? WHERE role=? AND owner_token=?",
                (until, now, role, owner_token),
            )
        return updated.rowcount == 1

    def release(self, role: str, owner_token: str) -> bool:
        with self.store.transaction(immediate=True) as connection:
            deleted = connection.execute(
                "DELETE FROM worker_leases WHERE role=? AND owner_token=?", (role, owner_token)
            )
        return deleted.rowcount == 1

    def inspect(self, role: str) -> dict | None:
        with self.store.connect() as connection:
            row = connection.execute("SELECT * FROM worker_leases WHERE role=?", (role,)).fetchone()
        return dict(row) if row else None


def new_owner_token() -> str:
    return str(uuid.uuid4())


__all__ = ["SQLiteWorkerLeaseRepository", "WORKER_LEASE_HELD_EXIT_CODE", "new_owner_token"]
