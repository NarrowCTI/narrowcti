"""Compatibility surface for graph planning and provider contracts."""

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from .graph_index import GraphIndex


@runtime_checkable
class GraphProvider(Protocol):
    """Read-only graph capability consumed by current graph planning callers."""

    def known_keys_for_plan(self, plan: Mapping[str, object]) -> Mapping[str, object]:
        ...


__all__ = ["GraphIndex", "GraphProvider"]
