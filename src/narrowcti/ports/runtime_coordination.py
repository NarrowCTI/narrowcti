"""Focused process coordination contracts."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol


class WorkerLeaseRepository(Protocol):
    def acquire(self, role: str, owner_token: str, lease_seconds: int = 60) -> bool: ...

    def renew(self, role: str, owner_token: str, lease_seconds: int = 60) -> bool: ...

    def release(self, role: str, owner_token: str) -> bool: ...

    def inspect(self, role: str) -> dict | None: ...


class ProcessCoordinationRepository(Protocol):
    def acquire(
        self,
        scope: str,
        owner_token: str,
        timeout_seconds: float = 30.0,
        lease_seconds: int = 120,
    ) -> bool: ...

    def release(self, scope: str, owner_token: str) -> bool: ...

    def exclusive(
        self,
        scope: str,
        owner_token: str | None = None,
        timeout_seconds: float = 30.0,
        lease_seconds: int = 120,
    ) -> AbstractContextManager: ...


__all__ = ["ProcessCoordinationRepository", "WorkerLeaseRepository"]
