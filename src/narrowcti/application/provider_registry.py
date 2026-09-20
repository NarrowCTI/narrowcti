"""Minimal, lazy source registry used by the application runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass(frozen=True)
class SourceDefinition:
    key: str
    name: str
    factory: Callable[[], object]


class SourceRegistry:
    """Ordered source definitions whose factories are evaluated on execution."""

    def __init__(self, definitions: Iterable[SourceDefinition] | None = None):
        self._definitions: dict[str, SourceDefinition] = {}
        for definition in definitions or ():
            self.register(definition.key, definition.name, definition.factory)

    def register(self, key, name, factory):
        normalized_key = normalize_source_key(key)
        if normalized_key in self._definitions:
            raise ValueError(f"Source already registered: {normalized_key}")
        self._definitions[normalized_key] = SourceDefinition(
            key=normalized_key,
            name=name,
            factory=factory,
        )
        return self

    def get(self, key):
        normalized_key = normalize_source_key(key)
        if normalized_key not in self._definitions:
            raise KeyError(f"Unknown source: {normalized_key}")
        return self._definitions[normalized_key]

    @property
    def source_keys(self):
        return tuple(self._definitions.keys())


def normalize_source_key(value):
    return str(value).strip().lower()


__all__ = ["SourceDefinition", "SourceRegistry", "normalize_source_key"]
