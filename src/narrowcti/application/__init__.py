"""Application-layer seams for NarrowCTI runtime orchestration."""

from .runtime_roles import OPS, WEB, WORKER, RuntimeRole, normalize_role

__all__ = ["OPS", "WEB", "WORKER", "RuntimeRole", "normalize_role"]
