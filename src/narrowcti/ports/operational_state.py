"""Minimal read contract for the latest authoritative operational snapshot."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class OperationalStateReader(Protocol):
    """Read a bounded, already-safe snapshot published by the Gateway role."""

    def read(self) -> Mapping[str, object] | None: ...


__all__ = ["OperationalStateReader"]
