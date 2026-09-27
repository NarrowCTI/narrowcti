"""Minimal application-facing job repository contracts."""

from __future__ import annotations

from typing import Any, Mapping, Protocol


QUARANTINE_EXPORT_JOB = "quarantine.export"


class JobRepository(Protocol):
    """Port for bounded, idempotent Community jobs."""

    def submit(
        self,
        job_type: str,
        source: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> Mapping[str, Any]: ...

    def get(self, job_id: str) -> Mapping[str, Any] | None: ...

    def claim_next(self, owner: str, lease_seconds: int = 300) -> Mapping[str, Any] | None: ...

    def complete(
        self,
        job_id: str,
        owner: str,
        attempt: int,
        result: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...

    def fail(
        self,
        job_id: str,
        owner: str,
        attempt: int,
        error: str,
    ) -> Mapping[str, Any]: ...


__all__ = ["JobRepository", "QUARANTINE_EXPORT_JOB"]
