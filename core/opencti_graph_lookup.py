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

MALWARE_LOOKUP_QUERY = """
query NarrowCTIMalwareGraphLookup($filters: FilterGroup) {
  malwares(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

MALWARE_SEARCH_QUERY = """
query NarrowCTIMalwareGraphSearch($search: String) {
  malwares(search: $search, first: 10) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        aliases
      }
    }
  }
}
"""

TOOL_LOOKUP_QUERY = """
query NarrowCTIToolGraphLookup($filters: FilterGroup) {
  tools(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

TOOL_SEARCH_QUERY = """
query NarrowCTIToolGraphSearch($search: String) {
  tools(search: $search, first: 10) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        aliases
      }
    }
  }
}
"""

THREAT_ACTOR_LOOKUP_QUERY = """
query NarrowCTIThreatActorGraphLookup($filters: FilterGroup) {
  threatActors(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

THREAT_ACTOR_SEARCH_QUERY = """
query NarrowCTIThreatActorGraphSearch($search: String) {
  threatActors(search: $search, first: 10) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        aliases
      }
    }
  }
}
"""

INTRUSION_SET_LOOKUP_QUERY = """
query NarrowCTIIntrusionSetGraphLookup($filters: FilterGroup) {
  intrusionSets(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

INTRUSION_SET_SEARCH_QUERY = """
query NarrowCTIIntrusionSetGraphSearch($search: String) {
  intrusionSets(search: $search, first: 10) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        aliases
      }
    }
  }
}
"""

VULNERABILITY_LOOKUP_QUERY = """
query NarrowCTIVulnerabilityGraphLookup($filters: FilterGroup) {
  vulnerabilities(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

LOCATION_LOOKUP_QUERY = """
query NarrowCTILocationGraphLookup($filters: FilterGroup) {
  locations(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
VULNERABILITY_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CURATED_ALIAS_GROUPS = {
    "malware": [
        {
            "preferred": "Lumma Stealer",
            "aliases": ("Lumma Stealer", "LummaStealer", "LummaC2", "Lumma C2"),
            "search": "Lumma",
        }
    ],
}


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
        if stix_object_type == "malware":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="malware",
                collection_name="malwares",
                query_text=MALWARE_LOOKUP_QUERY,
                search_query_text=MALWARE_SEARCH_QUERY,
            )
        if stix_object_type == "tool":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="tool",
                collection_name="tools",
                query_text=TOOL_LOOKUP_QUERY,
                search_query_text=TOOL_SEARCH_QUERY,
            )
        if stix_object_type == "threat-actor":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="threat-actor",
                collection_name="threatActors",
                query_text=THREAT_ACTOR_LOOKUP_QUERY,
                search_query_text=THREAT_ACTOR_SEARCH_QUERY,
                enable_alias_search_by_default=True,
            )
        if stix_object_type == "intrusion-set":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="intrusion-set",
                collection_name="intrusionSets",
                query_text=INTRUSION_SET_LOOKUP_QUERY,
                search_query_text=INTRUSION_SET_SEARCH_QUERY,
                enable_alias_search_by_default=True,
            )
        if stix_object_type == "vulnerability":
            return self.find_vulnerability(candidate)
        if stix_object_type == "location":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="location",
                collection_name="locations",
                query_text=LOCATION_LOOKUP_QUERY,
            )
        return None

    def find_attack_pattern(self, candidate):
        attack_id = attack_pattern_external_id(candidate)
        if attack_id:
            return self.query_attack_pattern("x_mitre_id", attack_id, "mitre_attack_id")

        standard_id = attack_pattern_standard_id(candidate)
        if standard_id:
            return self.query_attack_pattern("standard_id", standard_id, "standard_id")

        return None

    def find_vulnerability(self, candidate):
        standard_id = graph_object_standard_id(candidate, "vulnerability")
        if standard_id:
            return self.query_named_graph_object(
                VULNERABILITY_LOOKUP_QUERY,
                "vulnerabilities",
                "vulnerability",
                "standard_id",
                standard_id,
                "standard_id",
            )

        vulnerability_id = vulnerability_external_id(candidate)
        if vulnerability_id:
            return self.query_named_graph_object(
                VULNERABILITY_LOOKUP_QUERY,
                "vulnerabilities",
                "vulnerability",
                "name",
                vulnerability_id,
                "cve_id",
            )

        return None

    def find_named_graph_object(
        self,
        candidate,
        stix_object_type,
        collection_name,
        query_text,
        search_query_text="",
        enable_alias_search_by_default=False,
    ):
        standard_id = graph_object_standard_id(candidate, stix_object_type)
        if standard_id:
            return self.query_named_graph_object(
                query_text,
                collection_name,
                stix_object_type,
                "standard_id",
                standard_id,
                "standard_id",
            )

        alias_match = self.find_named_graph_object_by_alias(
            candidate,
            stix_object_type,
            collection_name,
            search_query_text,
            enable_by_default=enable_alias_search_by_default,
        )
        if alias_match:
            return alias_match

        name = graph_object_name(candidate)
        if name:
            return self.query_named_graph_object(
                query_text,
                collection_name,
                stix_object_type,
                "name",
                name,
                "name",
            )

        return None

    def find_named_graph_object_by_alias(
        self,
        candidate,
        stix_object_type,
        collection_name,
        search_query_text,
        enable_by_default=False,
    ):
        if not search_query_text:
            return None

        lookup = graph_object_alias_lookup(
            candidate,
            stix_object_type,
            enable_by_default=enable_by_default,
        )
        if not lookup["enabled"]:
            return None
        for search_value in lookup["search_values"]:
            result = self.query_named_graph_object_search(
                search_query_text,
                collection_name,
                stix_object_type,
                search_value,
            )
            match = select_alias_match(result, lookup)
            if match:
                return match
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

    def query_named_graph_object_search(
        self,
        query_text,
        collection_name,
        stix_object_type,
        search_value,
    ):
        try:
            result = self.api_client.query(query_text, {"search": search_value})
        except Exception as exc:
            self.logger(
                "OpenCTI graph lookup failed: "
                f"type={stix_object_type} search={search_value} error={exc}"
            )
            return []

        return nodes_from(result, collection_name)

    def query_named_graph_object(
        self,
        query_text,
        collection_name,
        stix_object_type,
        key,
        value,
        match_type,
    ):
        variables = {"filters": filter_eq(key, value)}
        try:
            result = self.api_client.query(query_text, variables)
        except Exception as exc:
            self.logger(
                "OpenCTI graph lookup failed: "
                f"type={stix_object_type} key={key} value={value} error={exc}"
            )
            return None

        node = first_node(result, collection_name)
        if not node:
            return None

        return {
            "opencti_id": clean_string(node.get("id")),
            "standard_id": clean_string(node.get("standard_id")),
            "entity_type": clean_string(node.get("entity_type")),
            "name": clean_string(node.get("name")),
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


def nodes_from(result, collection_name):
    edges = (((result or {}).get("data") or {}).get(collection_name) or {}).get(
        "edges",
        [],
    )
    nodes = []
    for edge in edges:
        node = mapping_from(edge.get("node") if isinstance(edge, Mapping) else None)
        if node:
            nodes.append(node)
    return nodes


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


def vulnerability_external_id(candidate):
    candidate = mapping_from(candidate)
    for value in (
        candidate.get("value"),
        candidate.get("name"),
        candidate.get("display_name"),
    ):
        normalized = normalize_vulnerability_id(value)
        if normalized:
            return normalized

    attributes = mapping_from(candidate.get("attributes"))
    for key in ("external_id", "cve_id", "name", "value"):
        normalized = normalize_vulnerability_id(attributes.get(key))
        if normalized:
            return normalized

    for reference in attributes.get("external_references") or []:
        reference = mapping_from(reference)
        source_name = clean_string(reference.get("source_name")).lower()
        if source_name not in {"cve", "nvd", "mitre-cve"}:
            continue
        normalized = normalize_vulnerability_id(reference.get("external_id"))
        if normalized:
            return normalized

    return ""


def normalize_vulnerability_id(value):
    match = VULNERABILITY_ID_RE.search(clean_string(value))
    return match.group(0).upper() if match else ""


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


def graph_object_standard_id(candidate, stix_object_type):
    candidate = mapping_from(candidate)
    prefix = f"{clean_string(stix_object_type).lower()}--"
    for value in (candidate.get("standard_id"), candidate.get("stix_id")):
        standard_id = normalize_stix_id(value, prefix)
        if standard_id:
            return standard_id

    attributes = mapping_from(candidate.get("attributes"))
    for key in ("standard_id", "stix_id"):
        standard_id = normalize_stix_id(attributes.get(key), prefix)
        if standard_id:
            return standard_id

    return ""


def graph_object_name(candidate):
    candidate = mapping_from(candidate)
    for value in (
        candidate.get("name"),
        candidate.get("value"),
        candidate.get("display_name"),
    ):
        name = clean_string(value)
        if name:
            return name
    return ""


def graph_object_alias_lookup(candidate, stix_object_type, enable_by_default=False):
    candidate_terms = graph_object_alias_terms(candidate)
    alias_group = find_curated_alias_group(stix_object_type, candidate_terms)
    explicit_alias_values = graph_object_explicit_alias_values(candidate)
    if alias_group:
        group_terms = {
            normalize_alias_value(term)
            for term in alias_group.get("aliases") or []
            if normalize_alias_value(term)
        }
        candidate_terms.update(group_terms)
        preferred = normalize_alias_value(alias_group.get("preferred"))
        search_values = ordered_search_values(
            [
                alias_group.get("search"),
                alias_group.get("preferred"),
                *alias_group.get("aliases", ()),
            ]
        )
    else:
        preferred = ""
        search_values = ordered_search_values(graph_object_alias_raw_values(candidate))

    return {
        "candidate_terms": candidate_terms,
        "enabled": bool(alias_group or explicit_alias_values or enable_by_default),
        "preferred": preferred,
        "search_values": search_values,
    }


def graph_object_alias_terms(candidate):
    return {
        normalize_alias_value(value)
        for value in graph_object_alias_raw_values(candidate)
        if normalize_alias_value(value)
    }


def graph_object_alias_raw_values(candidate):
    candidate = mapping_from(candidate)
    values = [
        candidate.get("name"),
        candidate.get("value"),
        candidate.get("display_name"),
    ]
    values.extend(graph_object_explicit_alias_values(candidate))
    return [clean_string(value) for value in values if clean_string(value)]


def graph_object_explicit_alias_values(candidate):
    candidate = mapping_from(candidate)
    values = []
    attributes = mapping_from(candidate.get("attributes"))
    for key in ("aliases", "alias", "x_opencti_aliases"):
        values.extend(list_values(attributes.get(key)))
    return [clean_string(value) for value in values if clean_string(value)]


def find_curated_alias_group(stix_object_type, candidate_terms):
    for group in CURATED_ALIAS_GROUPS.get(clean_string(stix_object_type).lower(), []):
        group_terms = {
            normalize_alias_value(term)
            for term in group.get("aliases") or []
            if normalize_alias_value(term)
        }
        if candidate_terms.intersection(group_terms):
            return group
    return {}


def select_alias_match(nodes, lookup):
    candidate_terms = lookup.get("candidate_terms") or set()
    preferred = lookup.get("preferred") or ""
    matches = []
    for node in nodes:
        node_terms = graph_node_alias_terms(node)
        if not candidate_terms.intersection(node_terms):
            continue
        match = node_to_match(
            node,
            match_type="alias",
            match_value=clean_string(node.get("name")),
        )
        if preferred and normalize_alias_value(node.get("name")) == preferred:
            return match
        matches.append(match)

    if len(matches) == 1:
        return matches[0]
    return {}


def graph_node_alias_terms(node):
    node = mapping_from(node)
    values = [node.get("name")]
    values.extend(list_values(node.get("aliases")))
    return {
        normalize_alias_value(value)
        for value in values
        if normalize_alias_value(value)
    }


def node_to_match(node, match_type, match_value):
    return {
        "opencti_id": clean_string(node.get("id")),
        "standard_id": clean_string(node.get("standard_id")),
        "entity_type": clean_string(node.get("entity_type")),
        "name": clean_string(node.get("name")),
        "match_type": match_type,
        "match_value": match_value,
    }


def ordered_search_values(values):
    ordered = []
    seen = set()
    for value in values:
        value = clean_string(value)
        key = value.casefold()
        if value and key not in seen:
            ordered.append(value)
            seen.add(key)
    return ordered


def normalize_alias_value(value):
    return re.sub(r"[^a-z0-9]+", "", clean_string(value).casefold())


def list_values(value):
    if value in ("", None):
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def normalize_stix_id(value, prefix):
    value = clean_string(value)
    if value.startswith(prefix):
        return value
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
