"""Deterministic graph-semantic compilation without STIX/OpenCTI imports."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping

from .contracts import CompilationResult, ObjectSemantics, RelationshipSemantics


def _value(candidate: Mapping[str, object], *keys: str) -> str:
    for key in keys:
        value = candidate.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _candidate_key(candidate: Mapping[str, object], index: int) -> str:
    return _value(candidate, "fingerprint", "external_id", "value", "name") or f"candidate:{index}"


def compile_graph_semantics(
    candidates: Iterable[Mapping[str, object]],
    *,
    key_resolver: Callable[[Mapping[str, object], int], str] | None = None,
    existing_reference_resolver: Callable[[Mapping[str, object]], str | None] | None = None,
    deduplicate: bool = True,
) -> CompilationResult:
    """Compile accepted candidate mappings into semantic graph decisions.

    This is deliberately small: it does not infer relationships, rerun policy,
    calculate STIX IDs or construct platform objects.  Callers must provide
    already accepted candidates and explicit relationship metadata.
    """

    objects: list[ObjectSemantics] = []
    relationships: list[RelationshipSemantics] = []
    seen_keys: set[str] = set()
    skipped: list[str] = []

    for index, candidate in enumerate(candidates or ()):
        if not isinstance(candidate, Mapping):
            skipped.append(f"candidate:{index}")
            continue
        key = (
            key_resolver(candidate, index)
            if key_resolver is not None
            else _candidate_key(candidate, index)
        )
        if deduplicate and key in seen_keys:
            skipped.append(key)
            continue
        seen_keys.add(key)
        semantic_type = _value(candidate, "stix_object_type", "entity_type") or "unknown"
        objects.append(
            ObjectSemantics(
                key=key,
                semantic_type=semantic_type,
                name=_value(candidate, "display_name", "name", "value"),
                value=_value(candidate, "value"),
                attributes=dict(candidate.get("attributes") or {}),
                existing_reference=(
                    existing_reference_resolver(candidate)
                    if existing_reference_resolver is not None
                    else _value(candidate, "existing_opencti_ref", "existing_ref") or None
                ),
            )
        )

        source_key = _value(candidate, "source_key")
        target_key = _value(candidate, "target_key")
        relationship_type = _value(candidate, "relationship_type")
        if source_key and target_key and relationship_type:
            relationships.append(
                RelationshipSemantics(
                    source_key=source_key,
                    relationship_type=relationship_type,
                    target_key=target_key,
                    confidence=candidate.get("relationship_confidence", candidate.get("confidence")),
                    attributes=dict(candidate.get("provenance") or {}),
                )
            )

    return CompilationResult(
        objects=tuple(objects),
        relationships=tuple(relationships),
        skipped=tuple(skipped),
    )


__all__ = ["compile_graph_semantics"]
