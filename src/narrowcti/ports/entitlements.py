"""Minimal entitlement provider contract."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class EntitlementProvider(Protocol):
    """Return capabilities explicitly granted by the active distribution."""

    def granted_capabilities(self) -> tuple[str, ...]:
        ...


__all__ = ["EntitlementProvider"]
