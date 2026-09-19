"""Minimal quarantine persistence contract."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class QuarantineStore(Protocol):
    """Operations required by processors, review and export orchestration."""

    def add(self, record: Any) -> Any:
        ...

    def records(self, status: str | None = None) -> list[dict[str, Any]]:
        ...

    def get(self, quarantine_id: str) -> dict[str, Any]:
        ...

    def reject(self, quarantine_id: str, reason: str, reviewer: str = "operator", require_reason: bool = True) -> dict[str, Any]:
        ...

    def release(self, quarantine_id: str, reason: str, reviewer: str = "operator", require_reason: bool = True) -> dict[str, Any]:
        ...

    def release_indicators(
        self,
        quarantine_id: str,
        indicator_types: Any,
        reason: str,
        reviewer: str = "operator",
        require_reason: bool = True,
    ) -> dict[str, Any]:
        ...

    def mark_exported(
        self,
        quarantine_id: str,
        exported_indicator_count: int,
        dedup_duplicate_count: int = 0,
        exported_by: str = "gateway.quarantine",
    ) -> dict[str, Any]:
        ...


__all__ = ["QuarantineStore"]
