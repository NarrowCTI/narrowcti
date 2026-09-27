"""SQLite implementation of the bounded Community JobRepository."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from .sqlite_runtime_store import SQLiteRuntimeStore


TERMINAL_STATES = frozenset({"succeeded", "failed"})


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _decode(row):
    if row is None:
        return None
    data = dict(row)
    data["payload"] = json.loads(data.pop("payload_json"))
    result = data.pop("result_json")
    data["result"] = json.loads(result) if result else None
    return data


class SQLiteJobRepository:
    def __init__(self, store: SQLiteRuntimeStore):
        self.store = store

    def submit(
        self,
        job_type: str,
        source: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict:
        if not job_type or not idempotency_key:
            raise ValueError("job_type and idempotency_key are required")
        job_id = str(uuid.uuid4())
        created_at = utc_now()
        payload_json = json.dumps(dict(payload), sort_keys=True)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO jobs(
                    job_id, job_type, source, payload_json, idempotency_key,
                    status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (job_id, str(job_type), str(source or ""), payload_json, str(idempotency_key), created_at),
            )
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_type=? AND idempotency_key=?",
                (str(job_type), str(idempotency_key)),
            ).fetchone()
        return _decode(row)

    def get(self, job_id: str) -> dict | None:
        with self.store.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return _decode(row)

    def claim_next(self, owner: str, lease_seconds: int = 300) -> dict | None:
        if not owner:
            raise ValueError("job owner is required")
        now_epoch = time.time()
        now = utc_now()
        lease_until = now_epoch + max(int(lease_seconds), 1)
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT * FROM jobs
                WHERE status='pending'
                   OR (status='running' AND lease_until IS NOT NULL AND lease_until <= ?)
                ORDER BY created_at, job_id
                LIMIT 1
                """,
                (now_epoch,),
            ).fetchone()
            if row is None:
                return None
            attempt = int(row["attempt"] or 0) + 1
            updated = connection.execute(
                """
                UPDATE jobs
                SET status='running', claimed_at=?, claim_owner=?, lease_until=?,
                    started_at=COALESCE(started_at, ?), finished_at=NULL,
                    attempt=?, error=NULL
                WHERE job_id=?
                  AND (status='pending' OR (status='running' AND lease_until IS NOT NULL AND lease_until <= ?))
                """,
                (now, owner, lease_until, now, attempt, row["job_id"], now_epoch),
            )
            if updated.rowcount != 1:
                return None
            claimed = connection.execute("SELECT * FROM jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return _decode(claimed)

    def complete(self, job_id: str, owner: str, attempt: int, result: Mapping[str, Any] | None = None) -> dict:
        return self._finish(job_id, owner, attempt, "succeeded", result=result, error=None)

    def fail(self, job_id: str, owner: str, attempt: int, error: str) -> dict:
        return self._finish(job_id, owner, attempt, "failed", result=None, error=str(error))

    def _finish(self, job_id, owner, attempt, status, *, result, error):
        encoded_result = json.dumps(dict(result), sort_keys=True) if result is not None else None
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown job: {job_id}")
            if row["status"] in TERMINAL_STATES:
                if row["status"] == status and row["claim_owner"] == owner and int(row["attempt"]) == int(attempt):
                    return _decode(row)
                raise RuntimeError("job already has a conflicting terminal state")
            updated = connection.execute(
                """
                UPDATE jobs SET status=?, finished_at=?, result_json=?, error=?, lease_until=NULL
                WHERE job_id=? AND status='running' AND claim_owner=? AND attempt=?
                """,
                (status, utc_now(), encoded_result, error, job_id, owner, int(attempt)),
            )
            if updated.rowcount != 1:
                raise PermissionError("job owner or attempt is stale")
            completed = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return _decode(completed)


__all__ = ["SQLiteJobRepository", "TERMINAL_STATES", "utc_now"]
