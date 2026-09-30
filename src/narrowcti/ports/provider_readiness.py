"""Minimal structural contract for bounded, non-mutating provider probes."""

from __future__ import annotations

from typing import Protocol

from narrowcti.ports.source_explorer import ProviderDescriptor


class ProviderReadinessProbe(Protocol):
    def descriptor(self) -> ProviderDescriptor: ...

    def probe_readiness(self) -> int: ...


__all__ = ["ProviderReadinessProbe"]
