import argparse
import json
import os
import sys
from urllib.parse import urlparse

import requests


OPENCTI_GRAPHQL_PATH = "/graphql"
DIAMOND_QUADRANTS = ("adversary", "capability", "infrastructure", "victimology")

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

QUADRANT_TYPES = {
    "adversary": {
        "Campaign",
        "Intrusion-Set",
        "Threat-Actor-Group",
        "Threat-Actor-Individual",
    },
    "capability": {
        "Attack-Pattern",
        "Channel",
        "Course-Of-Action",
        "Data-Component",
        "Data-Source",
        "Malware",
        "Narrative",
        "Tool",
        "Vulnerability",
    },
    "infrastructure": {
        "Autonomous-System",
        "Domain-Name",
        "Infrastructure",
        "IPv4-Addr",
        "IPv6-Addr",
        "Url",
    },
    "victimology": {
        "Administrative-Area",
        "City",
        "Country",
        "Individual",
        "Organization",
        "Position",
        "Region",
        "Sector",
        "System",
    },
}

NAME_KEYS = (
    "name",
    "identity_name",
    "intrusion_name",
    "campaign_name",
    "malware_name",
    "tool_name",
    "channel_name",
    "attack_name",
    "infra_name",
    "sector_name",
    "country_name",
    "region_name",
    "city_name",
    "org_name",
    "event_name",
    "report_name",
    "as_name",
    "observable_value",
    "standard_id",
    "id",
)

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


def summarize_relationships(
    target,
    relationships,
    expected_quadrants=(),
    require_kill_chain=False,
):
    outbound = list(relationships.get("outbound") or [])
    inbound = list(relationships.get("inbound") or [])
    all_relationships = outbound + inbound
    quadrant_counts = {
        "adversary": 0,
        "capability": 0,
        "infrastructure": 0,
        "victimology": 0,
        "other": 0,
    }
    attack_patterns = []
    samples = []
    for relationship in all_relationships:
        source = relationship.get("from") or {}
        target_object = relationship.get("to") or {}
        other = target_object if source.get("id") == target.get("id") else source
        quadrant_counts[quadrant_for_object(other)] += 1
        if other.get("entity_type") == "Attack-Pattern":
            attack_label = " ".join(
                value
                for value in (
                    str(other.get("x_mitre_id") or ""),
                    object_label(other),
                )
                if value
            )
            if attack_label not in attack_patterns:
                attack_patterns.append(attack_label)
        samples.append(relationship_sample(target, relationship))
    return {
        "found": True,
        "target": object_summary(target),
        "relationship_count": len(all_relationships),
        "outbound_count": len(outbound),
        "inbound_count": len(inbound),
        "diamond_quadrant_counts": quadrant_counts,
        "kill_chain_attack_patterns": attack_patterns,
        "coverage": coverage_summary(
            quadrant_counts,
            attack_patterns,
            expected_quadrants=expected_quadrants,
            require_kill_chain=require_kill_chain,
        ),
        "sample_relationships": samples,
    }


def coverage_summary(
    quadrant_counts,
    attack_patterns,
    expected_quadrants=(),
    require_kill_chain=False,
):
    expected = normalize_quadrants(expected_quadrants)
    present = [
        quadrant
        for quadrant in DIAMOND_QUADRANTS
        if int((quadrant_counts or {}).get(quadrant, 0) or 0) > 0
    ]
    missing = [quadrant for quadrant in expected if quadrant not in present]
    kill_chain_present = bool(attack_patterns)
    status = "informational"
    if expected or require_kill_chain:
        status = "pass"
        if missing or (require_kill_chain and not kill_chain_present):
            status = "needs-evidence"
    return {
        "status": status,
        "expected_quadrants": list(expected),
        "present_quadrants": present,
        "missing_quadrants": missing,
        "kill_chain_required": bool(require_kill_chain),
        "kill_chain_present": kill_chain_present,
    }


def relationship_sample(target, relationship):
    source = relationship.get("from") or {}
    target_object = relationship.get("to") or {}
    return {
        "direction": "outbound" if source.get("id") == target.get("id") else "inbound",
        "relationship_type": relationship.get("relationship_type"),
        "from": object_ref(source),
        "to": object_ref(target_object),
    }


def relationship_edges(connection):
    return [edge.get("node") or {} for edge in (connection or {}).get("edges") or []]


def quadrant_for_object(value):
    entity_type = str((value or {}).get("entity_type") or "")
    for quadrant, types in QUADRANT_TYPES.items():
        if entity_type in types:
            return quadrant
    return "other"


def object_label(value):
    value = value or {}
    for key in NAME_KEYS:
        if value.get(key):
            return str(value[key])
    return ""


def object_ref(value):
    value = value or {}
    label = object_label(value) or "-"
    return f"{value.get('entity_type') or '-'}:{label}"


def object_summary(value):
    return {
        "id": value.get("id"),
        "standard_id": value.get("standard_id"),
        "entity_type": value.get("entity_type"),
        "name": object_label(value),
    }


def normalize_quadrants(value):
    if isinstance(value, str):
        raw_items = value.split(",")
    else:
        raw_items = value or ()
    quadrants = []
    for item in raw_items:
        quadrant = str(item or "").strip().lower()
        if quadrant and quadrant in DIAMOND_QUADRANTS and quadrant not in quadrants:
            quadrants.append(quadrant)
    return tuple(quadrants)


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only OpenCTI object relationship and Diamond context audit."
    )
    parser.add_argument("--opencti-url", default=os.getenv("OPENCTI_URL", ""))
    parser.add_argument("--opencti-token", default=os.getenv("OPENCTI_TOKEN", ""))
    parser.add_argument(
        "--type",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_TYPE", ""),
    )
    parser.add_argument(
        "--search",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_SEARCH", ""),
    )
    parser.add_argument(
        "--first",
        type=int,
        default=int(os.getenv("NARROWCTI_OPENCTI_AUDIT_FIRST", "100")),
    )
    parser.add_argument(
        "--output-file",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE", ""),
    )
    parser.add_argument(
        "--expected-quadrants",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_EXPECTED_QUADRANTS", ""),
        help="Comma-separated Diamond quadrants expected for this target.",
    )
    parser.add_argument(
        "--require-kill-chain",
        action=argparse.BooleanOptionalAction,
        default=env_bool("NARROWCTI_OPENCTI_AUDIT_REQUIRE_KILL_CHAIN", False),
        help="Require at least one direct ATT&CK Attack Pattern in the audit.",
    )
    return parser.parse_args(argv)


def ensure_utf8_stdout():
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


def main(argv=None):
    ensure_utf8_stdout()
    args = parse_args(argv)
    if not args.opencti_url:
        raise SystemExit("Missing --opencti-url or OPENCTI_URL")
    if not args.opencti_token:
        raise SystemExit("Missing --opencti-token or OPENCTI_TOKEN")
    if not args.type:
        raise SystemExit("Missing --type or NARROWCTI_OPENCTI_AUDIT_TYPE")
    if args.type not in TARGET_QUERIES:
        valid_types = ", ".join(sorted(TARGET_QUERIES))
        raise SystemExit(f"Invalid --type {args.type!r}. Valid values: {valid_types}")
    if not args.search:
        raise SystemExit("Missing --search or NARROWCTI_OPENCTI_AUDIT_SEARCH")
    report = build_relationship_audit(
        args.opencti_url,
        args.opencti_token,
        args.type,
        args.search,
        first=args.first,
        expected_quadrants=normalize_quadrants(args.expected_quadrants),
        require_kill_chain=args.require_kill_chain,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output_file:
        parent = os.path.dirname(args.output_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.output_file, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    print(rendered)


if __name__ == "__main__":
    main()
