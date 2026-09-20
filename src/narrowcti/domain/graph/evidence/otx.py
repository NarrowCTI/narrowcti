# ruff: noqa: F401,F403,F405
from collections.abc import Mapping
from .common import *  # noqa: F403,F401

def otx_entity_evidence(entities, source_key=""):
    if not isinstance(entities, Mapping):
        return []
    records = []
    timeline_attributes = otx_timeline_attributes(entities)
    for item in entities.get("records") or []:
        if not isinstance(item, Mapping):
            continue
        attributes = {
            **timeline_attributes,
            **compact_mapping(item.get("attributes")),
        }
        record = evidence_record(
            entity_type=item.get("entity_type"),
            value=item.get("value"),
            source_key=source_key,
            source_name="otx",
            source_field=item.get("source_field"),
            confidence=item.get("confidence"),
            display_name=item.get("display_name"),
            attributes=attributes,
            stix_object_type=item.get("stix_object_type"),
            relationship_type=item.get("relationship_type"),
        )
        if record:
            records.append(record)
    return records

def otx_timeline_attributes(entities):
    lifecycle = compact_mapping(entities.get("lifecycle"))
    observation_window = compact_mapping(entities.get("indicator_observation_window"))
    return compact_mapping(
        {
            "source_created": lifecycle.get("created"),
            "source_modified": lifecycle.get("modified"),
            "first_seen_min": observation_window.get("first_seen_min"),
            "last_seen_max": observation_window.get("last_seen_max"),
        }
    )
