import json
import os
from collections.abc import Mapping

from core.decision_audit import utc_now


GRAPH_ENTITIES_KEY = "graph_entities"
GRAPH_RELATIONSHIPS_KEY = "graph_relationships"


def default_graph_state():
    return {
        GRAPH_ENTITIES_KEY: {},
        GRAPH_RELATIONSHIPS_KEY: {},
    }


def normalize_graph_state(data):
    if not isinstance(data, dict):
        return default_graph_state()
    if GRAPH_ENTITIES_KEY not in data or not isinstance(data[GRAPH_ENTITIES_KEY], dict):
        data[GRAPH_ENTITIES_KEY] = {}
    if GRAPH_RELATIONSHIPS_KEY not in data or not isinstance(
        data[GRAPH_RELATIONSHIPS_KEY],
        dict,
    ):
        data[GRAPH_RELATIONSHIPS_KEY] = {}
    return data


def load_graph_state(state_file):
    if not state_file or not os.path.exists(state_file):
        return default_graph_state()
    with open(state_file, "r", encoding="utf-8") as file_obj:
        try:
            data = json.load(file_obj)
        except Exception:
            return default_graph_state()
    return normalize_graph_state(data)


def save_graph_state(state_file, state):
    if not state_file:
        raise ValueError("state file is required")
    directory = os.path.dirname(state_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(state_file, "w", encoding="utf-8") as file_obj:
        json.dump(normalize_graph_state(state), file_obj, sort_keys=True)


class GraphDeduplicationIndex:
    def __init__(self, state_file):
        self.state_file = state_file
        self.state = load_graph_state(state_file)

    def refresh(self):
        self.state = load_graph_state(self.state_file)

    def has_entity(self, entity_key):
        self.refresh()
        return clean_string(entity_key) in self.state[GRAPH_ENTITIES_KEY]

    def has_relationship(self, relationship_key):
        self.refresh()
        return clean_string(relationship_key) in self.state[GRAPH_RELATIONSHIPS_KEY]

    def entity_record(self, entity_key):
        self.refresh()
        record = self.state[GRAPH_ENTITIES_KEY].get(clean_string(entity_key))
        return dict(record) if isinstance(record, dict) else None

    def relationship_record(self, relationship_key):
        self.refresh()
        record = self.state[GRAPH_RELATIONSHIPS_KEY].get(clean_string(relationship_key))
        return dict(record) if isinstance(record, dict) else None

    def known_keys_for_plan(self, plan):
        self.refresh()
        entity_keys = set()
        relationship_keys = set()
        for action in plan_actions(plan):
            dedup = action_deduplication(action)
            entity_key = clean_string(dedup.get("entity_key"))
            relationship_key = clean_string(dedup.get("relationship_key"))
            if entity_key and entity_key in self.state[GRAPH_ENTITIES_KEY]:
                entity_keys.add(entity_key)
            if (
                relationship_key
                and relationship_key in self.state[GRAPH_RELATIONSHIPS_KEY]
            ):
                relationship_keys.add(relationship_key)
        return {
            "entity_keys": sorted(entity_keys),
            "relationship_keys": sorted(relationship_keys),
        }

    def mark_plan(self, plan, source_key="", external_id="", title=""):
        self.refresh()
        changed = False
        now = utc_now()
        source_key = clean_string(source_key)
        external_id = clean_string(external_id)
        title = clean_string(title)
        added = {
            "entities": 0,
            "relationships": 0,
        }

        for action in plan_actions(plan):
            if clean_string(action.get("action")) not in ("would_create", "exported"):
                continue
            candidate = mapping_from(action.get("candidate"))
            dedup = action_deduplication(action)
            entity_key = clean_string(dedup.get("entity_key"))
            relationship_key = clean_string(dedup.get("relationship_key"))
            if entity_key:
                was_added, changed_record = upsert_graph_record(
                    self.state[GRAPH_ENTITIES_KEY],
                    entity_key,
                    candidate,
                    source_key=source_key,
                    external_id=external_id,
                    title=title,
                    recorded_at=now,
                )
                added["entities"] += 1 if was_added else 0
                changed = changed or changed_record
            if relationship_key:
                was_added, changed_record = upsert_graph_record(
                    self.state[GRAPH_RELATIONSHIPS_KEY],
                    relationship_key,
                    candidate,
                    source_key=source_key,
                    external_id=external_id,
                    title=title,
                    recorded_at=now,
                )
                added["relationships"] += 1 if was_added else 0
                changed = changed or changed_record

        if changed:
            save_graph_state(self.state_file, self.state)
        return added


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
