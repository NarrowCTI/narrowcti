"""Safe domain record for deployment-managed local operator accounts."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OperatorRecord:
    operator_id: str
    username: str
    password_hash: str = field(repr=False)
    roles: frozenset[str]
    enabled: bool
    auth_revision: int
    created_at: str
    updated_at: str
    password_changed_at: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "operator_id": self.operator_id,
            "username": self.username,
            "roles": sorted(self.roles),
            "enabled": self.enabled,
            "auth_revision": self.auth_revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "password_changed_at": self.password_changed_at,
        }


__all__ = ["OperatorRecord"]
