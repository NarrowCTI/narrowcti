"""Pure graph deduplication and plan-record primitives.

This module deliberately contains no filesystem, JSON, clock, OpenCTI, or
legacy ``core`` dependency.  The concrete local index remains in
``core.graph_deduplication`` until the graph persistence wave.
"""

from collections.abc import Mapping


def upsert_graph_record(
    records,
    key,
    candidate,
    source_key="",
    external_id="",
    title="",
    recorded_at="",
):
    record = records.get(key)
    added = False
    changed = False
    if not isinstance(record, dict):
        record = {
            "key": key,
            "first_seen": recorded_at,
            "last_seen": recorded_at,
            "candidate": candidate_summary(candidate),
            "sources": [],
            "sightings": [],
        }
        records[key] = record
        added = True
        changed = True

    if not record.get("first_seen"):
        record["first_seen"] = recorded_at
        changed = True
    if record.get("last_seen") != recorded_at:
        record["last_seen"] = recorded_at
        changed = True
    if candidate and not record.get("candidate"):
        record["candidate"] = candidate_summary(candidate)
        changed = True

    if source_key:
        sources = record.setdefault("sources", [])
        if source_key not in sources:
            sources.append(source_key)
            sources.sort()
            changed = True

    if source_key or external_id or title:
        sightings = record.setdefault("sightings", [])
        sighting = {
            "source_key": source_key,
            "external_id": external_id,
            "title": title,
            "recorded_at": recorded_at,
        }
        key_tuple = source_sighting_key(sighting)
        exists = any(
            source_sighting_key(existing) == key_tuple
            for existing in sightings
            if isinstance(existing, Mapping)
        )
        if not exists:
            sightings.append(sighting)
            changed = True

    return added, changed


def plan_actions(plan):
    plan = mapping_from(plan)
    return [
        dict(action)
        for action in plan.get("actions") or []
        if isinstance(action, Mapping)
    ]


def action_deduplication(action):
    dedup = action.get("deduplication")
    return dict(dedup) if isinstance(dedup, Mapping) else {}


def candidate_summary(candidate):
    candidate = mapping_from(candidate)
    summary = {}
    for field in (
        "fingerprint",
        "entity_type",
        "value",
        "name",
        "stix_object_type",
        "relationship_type",
        "confidence",
        "relationship_confidence",
        "external_id",
        "title",
    ):
        value = candidate.get(field)
        if value not in ("", None, [], {}):
            summary[field] = value
    return summary


def source_sighting_key(sighting):
    return (
        clean_string(sighting.get("source_key")),
        clean_string(sighting.get("external_id")),
    )


def mapping_from(value):
    return dict(value) if isinstance(value, Mapping) else {}


def clean_string(value):
    return " ".join(str(value or "").strip().split())


__all__ = [
    "action_deduplication",
    "candidate_summary",
    "clean_string",
    "mapping_from",
    "plan_actions",
    "source_sighting_key",
    "upsert_graph_record",
]
