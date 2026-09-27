"""Minimal application-facing job repository contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Protocol


QUARANTINE_EXPORT_JOB = "quarantine.export"


def quarantine_export_idempotency_key(quarantine_id: str, released_indicators) -> str:
    """Build a stable, value-free identity for a released artifact set."""
    canonical = set()
    for item in released_indicators or ():
        data = dict(item)
        canonical.add(
            (
                str(data.get("type") or data.get("indicator_type") or data.get("observable_type") or "").strip().lower(),
                str(data.get("indicator") or data.get("value") or "").strip(),
            )
        )
    canonical = [
        {"type": value[0], "indicator": value[1]}
        for value in sorted(canonical)
    ]
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{QUARANTINE_EXPORT_JOB}:{quarantine_id}:{digest}"


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

    def renew(self, job_id: str, owner: str, attempt: int, lease_seconds: int = 300) -> bool: ...

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


__all__ = ["JobRepository", "QUARANTINE_EXPORT_JOB", "quarantine_export_idempotency_key"]
