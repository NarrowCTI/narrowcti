import ipaddress
import re
from collections.abc import Mapping

from core.graph_deduplication import action_deduplication, plan_actions
from core.graph_export_plan import graph_entity_key, graph_relationship_source_anchor


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

THREAT_ACTOR_GROUP_LOOKUP_QUERY = """
query NarrowCTIThreatActorGroupGraphLookup($filters: FilterGroup) {
  threatActorsGroup(first: 1, filters: $filters) {
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

THREAT_ACTOR_GROUP_SEARCH_QUERY = """
query NarrowCTIThreatActorGroupGraphSearch($search: String) {
  threatActorsGroup(search: $search, first: 10) {
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

THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY = """
query NarrowCTIThreatActorIndividualGraphLookup($filters: FilterGroup) {
  threatActorsIndividuals(first: 1, filters: $filters) {
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

THREAT_ACTOR_INDIVIDUAL_SEARCH_QUERY = """
query NarrowCTIThreatActorIndividualGraphSearch($search: String) {
  threatActorsIndividuals(search: $search, first: 10) {
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

CAMPAIGN_LOOKUP_QUERY = """
query NarrowCTICampaignGraphLookup($filters: FilterGroup) {
  campaigns(first: 1, filters: $filters) {
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

CHANNEL_LOOKUP_QUERY = """
query NarrowCTIChannelGraphLookup($filters: FilterGroup) {
  channels(first: 1, filters: $filters) {
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

COURSE_OF_ACTION_LOOKUP_QUERY = """
query NarrowCTICourseOfActionGraphLookup($filters: FilterGroup) {
  coursesOfAction(first: 1, filters: $filters) {
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

DATA_COMPONENT_LOOKUP_QUERY = """
query NarrowCTIDataComponentGraphLookup($filters: FilterGroup) {
  dataComponents(first: 1, filters: $filters) {
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

DATA_SOURCE_LOOKUP_QUERY = """
query NarrowCTIDataSourceGraphLookup($filters: FilterGroup) {
  dataSources(first: 1, filters: $filters) {
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

EVENT_LOOKUP_QUERY = """
query NarrowCTIEventGraphLookup($filters: FilterGroup) {
  events(first: 1, filters: $filters) {
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

INFRASTRUCTURE_LOOKUP_QUERY = """
query NarrowCTIInfrastructureGraphLookup($filters: FilterGroup) {
  infrastructures(first: 1, filters: $filters) {
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

INFRASTRUCTURE_SEARCH_QUERY = """
query NarrowCTIInfrastructureGraphSearch($search: String) {
  infrastructures(search: $search, first: 10) {
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

NARRATIVE_LOOKUP_QUERY = """
query NarrowCTINarrativeGraphLookup($filters: FilterGroup) {
  narratives(first: 1, filters: $filters) {
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

ORGANIZATION_LOOKUP_QUERY = """
query NarrowCTIOrganizationGraphLookup($filters: FilterGroup) {
  organizations(first: 1, filters: $filters) {
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

SECTOR_LOOKUP_QUERY = """
query NarrowCTISectorGraphLookup($filters: FilterGroup) {
  sectors(first: 1, filters: $filters) {
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

SYSTEM_LOOKUP_QUERY = """
query NarrowCTISystemGraphLookup($filters: FilterGroup) {
  systems(first: 1, filters: $filters) {
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

INDIVIDUAL_LOOKUP_QUERY = """
query NarrowCTIIndividualGraphLookup($filters: FilterGroup) {
  individuals(first: 1, filters: $filters) {
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

SECURITY_PLATFORM_LOOKUP_QUERY = """
query NarrowCTISecurityPlatformGraphLookup($filters: FilterGroup) {
  securityPlatforms(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        security_platform_type
      }
    }
  }
}
"""

STIX_CYBER_OBSERVABLE_LOOKUP_QUERY = """
query NarrowCTIStixCyberObservableGraphLookup($filters: FilterGroup) {
  stixCyberObservables(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        observable_value
      }
    }
  }
}
"""

STIX_CYBER_OBSERVABLE_SEARCH_QUERY = """
query NarrowCTIStixCyberObservableGraphSearch($search: String) {
  stixCyberObservables(search: $search, first: 20) {
    edges {
      node {
        id
        standard_id
        entity_type
        observable_value
      }
    }
  }
}
"""

RELATIONSHIP_LOOKUP_QUERY = """
query NarrowCTIRelationshipGraphLookup(
  $fromIds: [String]
  $toIds: [String]
  $first: Int!
) {
  stixCoreRelationships(first: $first, fromId: $fromIds, toId: $toIds) {
    edges {
      node {
        id
        standard_id
        relationship_type
      }
    }
  }
}
"""

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
VULNERABILITY_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
AUTONOMOUS_SYSTEM_RE = re.compile(r"\bAS\s*(\d{1,10})\b", re.IGNORECASE)
CURATED_ALIAS_GROUPS = {
    "intrusion-set": [
        {
            "preferred": "Lazarus Group",
            "aliases": (
                "Lazarus",
                "Lazarus Group",
                "HIDDEN COBRA",
                "Guardians of Peace",
                "ZINC",
                "Labyrinth Chollima",
                "NICKEL ACADEMY",
                "Diamond Sleet",
            ),
            "search": "Lazarus",
        }
    ],
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
        candidate_matches = {}
        relationship_matches = {}

        for action in plan_actions(plan):
            candidate = mapping_from(action.get("candidate"))
            if not candidate:
                continue
            match = self.find_candidate_cached(candidate, candidate_matches)
            if not match:
                continue

            dedup = action_deduplication(action)
            entity_key = clean_string(dedup.get("entity_key")) or graph_entity_key(
                candidate
            )
            relationship_key = clean_string(dedup.get("relationship_key"))
            if entity_key:
                entity_keys.add(entity_key)
            if relationship_key:
                relationship_match = self.find_candidate_relationship(
                    candidate,
                    match,
                    candidate_matches,
                    relationship_matches,
                )
                if relationship_match:
                    relationship_keys.add(relationship_key)
                    match = {
                        **match,
                        "relationship_exists": True,
                        "relationship_match": relationship_match,
                    }

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

    def find_candidate_cached(self, candidate, cache):
        key = candidate_lookup_key(candidate)
        if key not in cache:
            cache[key] = self.find_candidate(candidate)
        return cache[key]

    def find_candidate_relationship(
        self,
        candidate,
        target_match,
        candidate_matches,
        relationship_matches,
    ):
        source_candidate = relationship_source_candidate(candidate)
        relationship_type = clean_string(candidate.get("relationship_type")).lower()
        target_id = clean_string(target_match.get("opencti_id"))
        if not source_candidate or not relationship_type or not target_id:
            return None

        source_match = self.find_candidate_cached(source_candidate, candidate_matches)
        source_id = clean_string((source_match or {}).get("opencti_id"))
        if not source_id:
            return None

        key = (source_id, target_id, relationship_type)
        if key not in relationship_matches:
            relationship_matches[key] = self.query_relationship(
                source_id,
                target_id,
                relationship_type,
            )
        relationship_match = relationship_matches[key]
        if not relationship_match:
            return None
        return {
            **relationship_match,
            "source_opencti_id": source_id,
            "target_opencti_id": target_id,
        }

    def query_relationship(self, source_id, target_id, relationship_type):
        variables = {
            "fromIds": [source_id],
            "toIds": [target_id],
            "first": 20,
        }
        try:
            result = self.api_client.query(RELATIONSHIP_LOOKUP_QUERY, variables)
        except Exception as exc:
            self.logger(
                "OpenCTI relationship lookup failed: "
                f"from={source_id} to={target_id} "
                f"type={relationship_type} error={exc}"
            )
            return None

        for node in nodes_from(result, "stixCoreRelationships"):
            existing_type = clean_string(node.get("relationship_type")).lower()
            if existing_type == relationship_type:
                return {
                    "opencti_id": clean_string(node.get("id")),
                    "standard_id": clean_string(node.get("standard_id")),
                    "relationship_type": existing_type,
                }
        return None

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
            return self.find_threat_actor(candidate)
        if stix_object_type == "campaign":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="campaign",
                collection_name="campaigns",
                query_text=CAMPAIGN_LOOKUP_QUERY,
            )
        if stix_object_type == "channel":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="channel",
                collection_name="channels",
                query_text=CHANNEL_LOOKUP_QUERY,
            )
        if stix_object_type == "course-of-action":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="course-of-action",
                collection_name="coursesOfAction",
                query_text=COURSE_OF_ACTION_LOOKUP_QUERY,
            )
        if stix_object_type == "x-mitre-data-component":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="x-mitre-data-component",
                collection_name="dataComponents",
                query_text=DATA_COMPONENT_LOOKUP_QUERY,
            )
        if stix_object_type == "x-mitre-data-source":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="x-mitre-data-source",
                collection_name="dataSources",
                query_text=DATA_SOURCE_LOOKUP_QUERY,
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
        if stix_object_type == "infrastructure":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="infrastructure",
                collection_name="infrastructures",
                query_text=INFRASTRUCTURE_LOOKUP_QUERY,
                search_query_text=INFRASTRUCTURE_SEARCH_QUERY,
            )
        if stix_object_type == "event":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="event",
                collection_name="events",
                query_text=EVENT_LOOKUP_QUERY,
            )
        if stix_object_type == "narrative":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="narrative",
                collection_name="narratives",
                query_text=NARRATIVE_LOOKUP_QUERY,
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
        if stix_object_type == "identity":
            return self.find_identity(candidate)
        if stix_object_type == "security-platform":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="security-platform",
                collection_name="securityPlatforms",
                query_text=SECURITY_PLATFORM_LOOKUP_QUERY,
            )
        if stix_object_type == "autonomous-system":
            return self.find_autonomous_system(candidate)
        if stix_object_type == "observable":
            return self.find_observable(candidate)
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

    def find_autonomous_system(self, candidate):
        standard_id = graph_object_standard_id(candidate, "autonomous-system")
        if standard_id:
            return self.query_cyber_observable(
                "standard_id",
                standard_id,
                "standard_id",
            )

        observable_value = autonomous_system_observable_value(candidate)
        if observable_value:
            return self.query_cyber_observable("name", observable_value, "name")

        return None

    def find_observable(self, candidate):
        observable_type = observable_stix_object_type(candidate)
        if not observable_type:
            return None

        standard_id = graph_object_standard_id(candidate, observable_type)
        if standard_id:
            return self.query_cyber_observable(
                "standard_id",
                standard_id,
                "standard_id",
            )

        value = observable_value(candidate)
        if value:
            match = self.query_cyber_observable("value", value, "value")
            if match:
                return match
            if observable_type == "artifact":
                return self.query_cyber_observable_search(
                    value,
                    "value",
                    expected_entity_type="Artifact",
                    expected_observable_value=value,
                )

        return None

    def find_threat_actor(self, candidate):
        actor_class = threat_actor_class(candidate)
        if actor_class == "group":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="threat-actor",
                collection_name="threatActorsGroup",
                query_text=THREAT_ACTOR_GROUP_LOOKUP_QUERY,
                search_query_text=THREAT_ACTOR_GROUP_SEARCH_QUERY,
                enable_alias_search_by_default=True,
            )
        if actor_class == "individual":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="threat-actor",
                collection_name="threatActorsIndividuals",
                query_text=THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY,
                search_query_text=THREAT_ACTOR_INDIVIDUAL_SEARCH_QUERY,
                enable_alias_search_by_default=True,
            )
        return self.find_named_graph_object(
            candidate,
            stix_object_type="threat-actor",
            collection_name="threatActors",
            query_text=THREAT_ACTOR_LOOKUP_QUERY,
            search_query_text=THREAT_ACTOR_SEARCH_QUERY,
            enable_alias_search_by_default=True,
        )

    def find_identity(self, candidate):
        entity_type = clean_string(candidate.get("entity_type")).lower()
        if entity_type == "target_organization":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="identity",
                collection_name="organizations",
                query_text=ORGANIZATION_LOOKUP_QUERY,
            )
        if entity_type == "target_sector":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="identity",
                collection_name="sectors",
                query_text=SECTOR_LOOKUP_QUERY,
            )
        if entity_type == "target_system":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="identity",
                collection_name="systems",
                query_text=SYSTEM_LOOKUP_QUERY,
            )
        if entity_type == "target_individual":
            return self.find_named_graph_object(
                candidate,
                stix_object_type="identity",
                collection_name="individuals",
                query_text=INDIVIDUAL_LOOKUP_QUERY,
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

    def query_cyber_observable(self, key, value, match_type):
        variables = {"filters": filter_eq(key, value)}
        try:
            result = self.api_client.query(
                STIX_CYBER_OBSERVABLE_LOOKUP_QUERY,
                variables,
            )
        except Exception as exc:
            self.logger(
                "OpenCTI graph lookup failed: "
                f"type=stix-cyber-observable key={key} value={value} error={exc}"
            )
            return None

        node = first_node(result, "stixCyberObservables")
        if not node:
            return None

        observable_value = clean_string(node.get("observable_value"))
        return {
            "opencti_id": clean_string(node.get("id")),
            "standard_id": clean_string(node.get("standard_id")),
            "entity_type": clean_string(node.get("entity_type")),
            "name": observable_value,
            "observable_value": observable_value,
            "match_type": match_type,
            "match_value": value,
        }

    def query_cyber_observable_search(
        self,
        value,
        match_type,
        expected_entity_type="",
        expected_observable_value="",
    ):
        try:
            result = self.api_client.query(
                STIX_CYBER_OBSERVABLE_SEARCH_QUERY,
                {"search": value},
            )
        except Exception as exc:
            self.logger(
                "OpenCTI graph lookup failed: "
                f"type=stix-cyber-observable search={value} error={exc}"
            )
            return None

        expected_entity_type = clean_string(expected_entity_type).lower()
        expected_observable_value = clean_string(expected_observable_value)
        for node in nodes_from(result, "stixCyberObservables"):
            entity_type = clean_string(node.get("entity_type"))
            observable_value = clean_string(node.get("observable_value"))
            if expected_entity_type and entity_type.lower() != expected_entity_type:
                continue
            if expected_observable_value and observable_value != expected_observable_value:
                continue
            return {
                "opencti_id": clean_string(node.get("id")),
                "standard_id": clean_string(node.get("standard_id")),
                "entity_type": entity_type,
                "name": observable_value,
                "observable_value": observable_value,
                "match_type": match_type,
                "match_value": value,
            }

        return None


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


def autonomous_system_observable_value(candidate):
    candidate = mapping_from(candidate)
    attributes = mapping_from(candidate.get("attributes"))
    number = autonomous_system_number(candidate, attributes)
    if number is None:
        return ""
    name = clean_string(
        attributes.get("as_name")
        or attributes.get("asn_name")
        or attributes.get("name")
        or candidate.get("name")
        or candidate.get("value")
    )
    as_prefix = f"AS{number}"
    if name and name != as_prefix and not name.upper().startswith(as_prefix.upper()):
        return f"{as_prefix} {name}"
    return name or as_prefix


def autonomous_system_number(candidate, attributes=None):
    candidate = mapping_from(candidate)
    attributes = mapping_from(
        attributes if attributes is not None else candidate.get("attributes")
    )
    for value in (
        attributes.get("number"),
        attributes.get("asn"),
        attributes.get("as_number"),
        attributes.get("autonomous_system_number"),
        candidate.get("value"),
        candidate.get("name"),
    ):
        parsed = parse_autonomous_system_number(value)
        if parsed is not None:
            return parsed
    return None


def parse_autonomous_system_number(value):
    text = clean_string(value)
    if not text:
        return None
    match = AUTONOMOUS_SYSTEM_RE.search(text)
    if not match and text.isdigit():
        match = re.match(r"^([0-9]{1,10})$", text)
    if not match:
        return None
    number = int(match.group(1))
    if number < 0 or number > 4294967295:
        return None
    return number


def observable_stix_object_type(candidate):
    candidate = mapping_from(candidate)
    attributes = mapping_from(candidate.get("attributes"))
    observable_type = clean_string(attributes.get("observable_type")).lower()
    entity_type = clean_string(candidate.get("entity_type")).lower()
    supported = {
        "artifact",
        "domain-name",
        "url",
        "ipv4-addr",
        "ipv6-addr",
        "email-addr",
        "file",
    }
    if observable_type in supported:
        return observable_type
    if entity_type in supported:
        return entity_type
    return infer_observable_stix_object_type(observable_value(candidate))


def infer_observable_stix_object_type(value):
    value = clean_string(value)
    if not value:
        return ""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        network = None
    if network:
        return "ipv4-addr" if network.version == 4 else "ipv6-addr"
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if "@" in value and not any(char.isspace() for char in value):
        return "email-addr"
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", value):
        return "domain-name"
    return ""


def observable_value(candidate):
    candidate = mapping_from(candidate)
    for value in (
        candidate.get("value"),
        candidate.get("name"),
        candidate.get("display_name"),
    ):
        cleaned = clean_string(value)
        if cleaned:
            return cleaned
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
    for value in (candidate.get("standard_id"), candidate.get("stix_id")):
        standard_id = normalize_graph_object_stix_id(value, stix_object_type)
        if standard_id:
            return standard_id

    attributes = mapping_from(candidate.get("attributes"))
    for key in ("standard_id", "stix_id"):
        standard_id = normalize_graph_object_stix_id(
            attributes.get(key),
            stix_object_type,
        )
        if standard_id:
            return standard_id

    return ""


def threat_actor_class(candidate):
    candidate = mapping_from(candidate)
    attributes = mapping_from(candidate.get("attributes"))
    for value in (
        attributes.get("threat_actor_class"),
        attributes.get("actor_class"),
        attributes.get("actor_type"),
        candidate.get("entity_type"),
    ):
        normalized = clean_string(value).casefold().replace("-", "_")
        if normalized in {
            "group",
            "threat_actor",
            "threat_actor_group",
            "threatactorgroup",
        }:
            return "group"
        if normalized in {
            "individual",
            "person",
            "human",
            "threat_actor_individual",
            "threatactorindividual",
        }:
            return "individual"
    return ""


def normalize_graph_object_stix_id(value, stix_object_type):
    for prefix in graph_object_standard_id_prefixes(stix_object_type):
        standard_id = normalize_stix_id(value, f"{prefix}--")
        if standard_id:
            return standard_id
    return ""


def graph_object_standard_id_prefixes(stix_object_type):
    stix_object_type = clean_string(stix_object_type).lower()
    canonical_prefixes = {
        "security-platform": ["identity", "security-platform"],
        "x-mitre-data-component": ["data-component", "x-mitre-data-component"],
        "x-mitre-data-source": ["data-source", "x-mitre-data-source"],
    }
    return canonical_prefixes.get(stix_object_type, [stix_object_type])


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


def candidate_lookup_key(candidate):
    candidate = mapping_from(candidate)
    return (
        clean_string(candidate.get("stix_object_type")).lower(),
        clean_string(candidate.get("value") or candidate.get("name")).casefold(),
        clean_string(candidate.get("standard_id") or candidate.get("stix_id")),
    )


def relationship_source_candidate(candidate):
    source_type, source_value = graph_relationship_source_anchor(candidate)
    if not source_type or not source_value:
        return {}
    return {
        "stix_object_type": source_type,
        "entity_type": source_type,
        "value": source_value,
        "name": source_value,
    }


def clean_string(value):
    return " ".join(str(value or "").strip().split())
