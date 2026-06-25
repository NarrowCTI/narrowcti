import re
from collections.abc import Mapping

from core.graph_deduplication import action_deduplication, plan_actions
from core.graph_export_plan import graph_entity_key


ATTACK_PATTERN_LOOKUP_QUERY = """
query NarrowCTIAttackPatternGraphLookup($filters: FilterGroup) {
  attackPatterns(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        x_mitre_id
      }
    }
  }
}
"""

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class OpenCTIGraphLookup:
    def __init__(self, api_client, logger=None):
        self.api_client = api_client
        self.logger = logger or (lambda message: None)

    def known_keys_for_plan(self, plan):
        entity_keys = set()
        relationship_keys = set()
        matches = []

        for action in plan_actions(plan):
            candidate = mapping_from(action.get("candidate"))
            if not candidate:
                continue
            match = self.find_candidate(candidate)
            if not match:
                continue

            dedup = action_deduplication(action)
            entity_key = clean_string(dedup.get("entity_key")) or graph_entity_key(
                candidate
            )
            relationship_key = clean_string(dedup.get("relationship_key"))
            if entity_key:
                entity_keys.add(entity_key)
            if relationship_key and match.get("relationship_exists"):
                relationship_keys.add(relationship_key)

            matches.append(
                {
                    "entity_key": entity_key,
                    "relationship_key": relationship_key,
                    "stix_object_type": clean_string(
                        candidate.get("stix_object_type")
                    ),
                    "value": clean_string(candidate.get("value")),
                    "match": match,
                }
            )

        return {
            "entity_keys": sorted(entity_keys),
            "relationship_keys": sorted(relationship_keys),
            "matches": matches,
        }

    def find_candidate(self, candidate):
        candidate = mapping_from(candidate)
        stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
        if stix_object_type == "attack-pattern":
            return self.find_attack_pattern(candidate)
        return None

    def find_attack_pattern(self, candidate):
        attack_id = attack_pattern_external_id(candidate)
        if attack_id:
            return self.query_attack_pattern("x_mitre_id", attack_id, "mitre_attack_id")

        standard_id = attack_pattern_standard_id(candidate)
        if standard_id:
            return self.query_attack_pattern("standard_id", standard_id, "standard_id")

        return None

    def query_attack_pattern(self, key, value, match_type):
        variables = {"filters": filter_eq(key, value)}
        try:
            result = self.api_client.query(ATTACK_PATTERN_LOOKUP_QUERY, variables)
        except Exception as exc:
            self.logger(
                "OpenCTI graph lookup failed: "
                f"type=attack-pattern key={key} value={value} error={exc}"
            )
            return None

        node = first_node(result, "attackPatterns")
        if not node:
            return None

        return {
            "opencti_id": clean_string(node.get("id")),
            "standard_id": clean_string(node.get("standard_id")),
            "entity_type": clean_string(node.get("entity_type")),
            "name": clean_string(node.get("name")),
            "x_mitre_id": clean_string(node.get("x_mitre_id")),
            "match_type": match_type,
            "match_value": value,
        }


class CompositeGraphLookup:
    def __init__(self, *lookups):
        self.lookups = [lookup for lookup in lookups if lookup]

    def known_keys_for_plan(self, plan):
        entity_keys = set()
        relationship_keys = set()
        matches = []

        for lookup in self.lookups:
            known = mapping_from(lookup.known_keys_for_plan(plan))
            for key in known.get("entity_keys") or []:
                key = clean_string(key)
                if key:
                    entity_keys.add(key)
            for key in known.get("relationship_keys") or []:
                key = clean_string(key)
                if key:
                    relationship_keys.add(key)
            for match in known.get("matches") or []:
                if isinstance(match, Mapping):
                    matches.append(dict(match))

        result = {
            "entity_keys": sorted(entity_keys),
            "relationship_keys": sorted(relationship_keys),
        }
        if matches:
            result["matches"] = matches
        return result

    def mark_exported_plan(self, plan, source_key="", external_id="", title=""):
        added = {"entities": 0, "relationships": 0}
        for lookup in self.lookups:
            marker = getattr(lookup, "mark_exported_plan", None)
            if not marker:
                continue
            result = mapping_from(
                marker(
                    plan,
                    source_key=source_key,
                    external_id=external_id,
                    title=title,
                )
            )
            added["entities"] += int(result.get("entities", 0) or 0)
            added["relationships"] += int(result.get("relationships", 0) or 0)
        return added


def filter_eq(key, value):
    return {
        "mode": "and",
        "filters": [
            {
                "key": key,
                "values": [value],
                "operator": "eq",
            }
        ],
        "filterGroups": [],
    }


def first_node(result, collection_name):
    edges = (((result or {}).get("data") or {}).get(collection_name) or {}).get(
        "edges",
        [],
    )
    for edge in edges:
        node = mapping_from(edge.get("node") if isinstance(edge, Mapping) else None)
        if node:
            return node
    return {}


def attack_pattern_external_id(candidate):
    candidate = mapping_from(candidate)
    for value in (
        candidate.get("external_id"),
        candidate.get("value"),
        candidate.get("name"),
    ):
        attack_id = normalize_attack_id(value)
        if attack_id:
            return attack_id

    attributes = mapping_from(candidate.get("attributes"))
    for key in ("attack_id", "mitre_id", "external_id", "x_mitre_id"):
        attack_id = normalize_attack_id(attributes.get(key))
        if attack_id:
            return attack_id

    for reference in attributes.get("external_references") or []:
        reference = mapping_from(reference)
        if clean_string(reference.get("source_name")).lower() != "mitre-attack":
            continue
        attack_id = normalize_attack_id(reference.get("external_id"))
        if attack_id:
            return attack_id

    return ""


def attack_pattern_standard_id(candidate):
    candidate = mapping_from(candidate)
    for value in (candidate.get("standard_id"), candidate.get("stix_id")):
        standard_id = normalize_attack_pattern_stix_id(value)
        if standard_id:
            return standard_id

    attributes = mapping_from(candidate.get("attributes"))
    for key in ("standard_id", "stix_id"):
        standard_id = normalize_attack_pattern_stix_id(attributes.get(key))
        if standard_id:
            return standard_id

    return ""


def normalize_attack_id(value):
    match = ATTACK_ID_RE.search(clean_string(value))
    return match.group(0).upper() if match else ""


def normalize_attack_pattern_stix_id(value):
    value = clean_string(value)
    if value.startswith("attack-pattern--"):
        return value
    return ""


def mapping_from(value):
    return dict(value) if isinstance(value, Mapping) else {}


def clean_string(value):
    return " ".join(str(value or "").strip().split())
