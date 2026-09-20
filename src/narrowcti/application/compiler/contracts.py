"""Minimal semantic IR used between policy output and serialization.

These records describe decisions made by compilation (object/relationship
semantics and report context).  They intentionally do not mirror ``stix2``
objects and do not contain STIX/OpenCTI fields such as ``created_by_ref`` or
``ExtensionDefinition``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class ObjectSemantics:
    key: str
    semantic_type: str
    name: str = ""
    value: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    existing_reference: str | None = None


@dataclass(frozen=True)
class RelationshipSemantics:
    source_key: str
    relationship_type: str
    target_key: str
    confidence: int | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReportContext:
    name: str
    description: str = ""
    score: int = 0
    source_date: str | None = None
    object_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompilationResult:
    objects: tuple[ObjectSemantics, ...] = ()
    relationships: tuple[RelationshipSemantics, ...] = ()
    report: ReportContext | None = None
    skipped: tuple[str, ...] = ()


__all__ = [
    "CompilationResult",
    "ObjectSemantics",
    "RelationshipSemantics",
    "ReportContext",
]
