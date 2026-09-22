"""Concrete OpenCTI GraphQL transport for relationship assurance."""

from __future__ import annotations

import json
import requests
from urllib.parse import urlparse

from narrowcti.application.assurance.opencti_relationship_audit import (
    object_label,
    relationship_edges,
    summarize_relationships,
)


OPENCTI_GRAPHQL_PATH = "/graphql"


TARGET_QUERIES = {
    "infrastructure": (
        "infrastructures",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "observable": (
        "stixCyberObservables",
        (
            "edges { node { id standard_id entity_type observable_value "
            "... on AutonomousSystem { as_name: name number } } }"
        ),
    ),
    "intrusion-set": (
        "intrusionSets",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "campaign": (
        "campaigns",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "threat-actor": (
        "threatActors",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "malware": (
        "malwares",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "attack-pattern": (
        "attackPatterns",
        "edges { node { id standard_id entity_type name x_mitre_id description } }",
    ),
    "sector": (
        "sectors",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "country": (
        "countries",
        "edges { node { id standard_id entity_type name description } }",
    ),
    "organization": (
        "organizations",
        "edges { node { id standard_id entity_type name description } }",
    ),
}


RELATIONSHIP_QUERY = """
query RelationshipAudit($ids: [String], $first: Int!) {
  outbound: stixCoreRelationships(first: $first, fromId: $ids) {
    edges { node { id standard_id relationship_type from { ...Obj } to { ...Obj } } }
  }
  inbound: stixCoreRelationships(first: $first, toId: $ids) {
    edges { node { id standard_id relationship_type from { ...Obj } to { ...Obj } } }
  }
}

fragment Obj on BasicObject {
  id
  standard_id
  entity_type
  ... on Identity { identity_name: name }
  ... on IntrusionSet { intrusion_name: name }
  ... on Campaign { campaign_name: name }
  ... on Malware { malware_name: name }
  ... on Tool { tool_name: name }
  ... on Channel { channel_name: name }
  ... on AttackPattern { attack_name: name x_mitre_id }
  ... on Infrastructure { infra_name: name }
  ... on Sector { sector_name: name }
  ... on Country { country_name: name }
  ... on Region { region_name: name }
  ... on City { city_name: name }
  ... on Organization { org_name: name }
  ... on Event { event_name: name }
  ... on Report { report_name: name }
  ... on StixCyberObservable { observable_value }
  ... on AutonomousSystem { as_name: name number }
}
"""


def build_target_query(collection, selection):
    return f"""
query RelationshipAuditTarget($search: String!, $first: Int!) {{
  {collection}(first: $first, search: $search) {{
    {selection}
  }}
}}
"""

def graphql_request(opencti_url, token, query, variables):
    endpoint = opencti_url.rstrip("/") + OPENCTI_GRAPHQL_PATH
    parsed_endpoint = urlparse(endpoint)
    if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.netloc:
        raise ValueError("OpenCTI URL must use an HTTP or HTTPS endpoint")
    response = requests.post(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"query": query, "variables": variables},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise RuntimeError(json.dumps(payload["errors"], ensure_ascii=False))
    return payload.get("data") or {}

def load_target(opencti_url, token, target_type, search, first=10):
    collection, selection = TARGET_QUERIES[target_type]
    data = graphql_request(
        opencti_url,
        token,
        build_target_query(collection, selection),
        {"search": search, "first": first},
    )
    nodes = relationship_edges(data.get(collection))
    exact = [
        node
        for node in nodes
        if object_label(node).casefold() == str(search).casefold()
        or str(node.get("observable_value") or "").casefold() == str(search).casefold()
    ]
    return exact[0] if exact else (nodes[0] if nodes else {})

def load_relationships(opencti_url, token, object_id, first=100):
    data = graphql_request(
        opencti_url,
        token,
        RELATIONSHIP_QUERY,
        {"ids": [object_id], "first": first},
    )
    return {
        "outbound": relationship_edges(data.get("outbound")),
        "inbound": relationship_edges(data.get("inbound")),
    }

def build_relationship_audit(
    opencti_url,
    token,
    target_type,
    search,
    first=100,
    expected_quadrants=(),
    require_kill_chain=False,
):
    target = load_target(opencti_url, token, target_type, search, first=10)
    if not target:
        return {
            "target_type": target_type,
            "search": search,
            "found": False,
        }
    relationships = load_relationships(opencti_url, token, target["id"], first=first)
    return summarize_relationships(
        target,
        relationships,
        expected_quadrants=expected_quadrants,
        require_kill_chain=require_kill_chain,
    )


__all__ = [
    "OPENCTI_GRAPHQL_PATH",
    "TARGET_QUERIES",
    "RELATIONSHIP_QUERY",
    "build_target_query",
    "graphql_request",
    "load_target",
    "load_relationships",
    "build_relationship_audit",
]

