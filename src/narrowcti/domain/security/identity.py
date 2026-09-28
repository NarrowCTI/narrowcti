"""Shared Community role semantics and local operator identity."""

from __future__ import annotations

from dataclasses import dataclass

VALID_ROLES = frozenset({"reader", "reviewer", "exporter", "admin"})
ROLE_PERMISSIONS = {
    "reader": frozenset({"review:read", "source:explore", "ingestion:preview"}),
    "reviewer": frozenset({
        "review:read", "source:explore", "ingestion:preview", "review:decide",
        "export:preview", "ingestion:dry_run",
    }),
    "exporter": frozenset({
        "review:read", "source:explore", "ingestion:preview", "export:preview", "export:execute",
    }),
    "admin": frozenset({"*"}),
}


def has_permission(roles, permission: str) -> bool:
    granted = set()
    for role in roles:
        granted.update(ROLE_PERMISSIONS.get(role, ()))
    return "*" in granted or permission in granted


@dataclass(frozen=True)
class LocalOperatorPrincipal:
    """Current authorization snapshot bound to a stable local operator id."""

    operator_id: str
    principal: str
    roles: frozenset[str]
    auth_revision: int

    @property
    def credential_id(self) -> str:
        """Stable per-operator key retained for existing job idempotency contracts."""
        return self.operator_id

    def has_permission(self, permission: str) -> bool:
        return has_permission(self.roles, permission)


__all__ = ["LocalOperatorPrincipal", "ROLE_PERMISSIONS", "VALID_ROLES", "has_permission"]
