"""Minimal graph plan/index contract."""

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class GraphIndex(Protocol):
    """Operations required by graph planning and successful export marking."""

    def known_keys_for_plan(self, plan: Mapping[str, object]) -> Mapping[str, object]:
        ...

    def mark_exported_plan(
        self,
        plan: Mapping[str, object],
        source_key: str = "",
        external_id: str = "",
        title: str = "",
    ) -> Mapping[str, object]:
        ...


__all__ = ["GraphIndex"]
