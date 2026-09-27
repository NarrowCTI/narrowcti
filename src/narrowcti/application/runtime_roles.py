"""Pure runtime-role contract shared by role compositions."""

from __future__ import annotations

from dataclasses import dataclass


WEB = "web"
WORKER = "worker"
OPS = "ops"
ROLE_NAMES = frozenset({WEB, WORKER, OPS})
WORKER_LEASE_HELD_EXIT_CODE = 75


@dataclass(frozen=True)
class RuntimeRole:
    name: str

    def __post_init__(self):
        normalized = str(self.name or "").strip().lower()
        if normalized not in ROLE_NAMES:
            raise ValueError(f"unsupported runtime role: {self.name}")
        object.__setattr__(self, "name", normalized)

    @property
    def is_web(self):
        return self.name == WEB

    @property
    def is_worker(self):
        return self.name == WORKER

    @property
    def is_ops(self):
        return self.name == OPS


def normalize_role(value: str | None, default: str = WORKER) -> str:
    normalized = str(value or default).strip().lower()
    if normalized not in ROLE_NAMES:
        raise ValueError(f"unsupported runtime role: {value}")
    return normalized


__all__ = ["OPS", "ROLE_NAMES", "RuntimeRole", "WEB", "WORKER", "WORKER_LEASE_HELD_EXIT_CODE", "normalize_role"]
