"""Minimal persistence contracts used by the Community runtime."""

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable


@runtime_checkable
class StateRepository(Protocol):
    """Base processed-item storage semantics."""

    def has_item(self, item_id: str) -> bool:
        ...

    def mark_item(self, item_id: str) -> None:
        ...


@runtime_checkable
class ArtifactIndex(Protocol):
    """Artifact filtering and post-export marking contract."""

    def filter_new_indicators(
        self,
        indicators: Sequence[Mapping[str, object]],
    ) -> tuple[list[Mapping[str, object]], int]:
        ...

    def mark_indicators(
        self,
        indicators: Sequence[Mapping[str, object]],
        source_key: str = "",
        external_id: str = "",
        title: str = "",
    ) -> int:
        ...


__all__ = ["ArtifactIndex", "StateRepository"]
