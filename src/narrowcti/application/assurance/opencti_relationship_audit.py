"""Pure OpenCTI relationship and Diamond evidence interpretation."""

from __future__ import annotations

DIAMOND_QUADRANTS = ("adversary", "capability", "infrastructure", "victimology")
QUADRANT_TYPES = {
    "adversary": {"Campaign", "Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual"},
    "capability": {
        "Attack-Pattern", "Channel", "Course-Of-Action", "Data-Component",
        "Data-Source", "Malware", "Narrative", "Tool", "Vulnerability",
    },
    "infrastructure": {
        "Autonomous-System", "Domain-Name", "Infrastructure", "IPv4-Addr",
        "IPv6-Addr", "Url",
    },
    "victimology": {
        "Administrative-Area", "City", "Country", "Individual", "Organization",
        "Position", "Region", "Sector", "System",
    },
}
NAME_KEYS = (
    "name", "identity_name", "intrusion_name", "campaign_name", "malware_name",
    "tool_name", "channel_name", "attack_name", "infra_name", "sector_name",
    "country_name", "region_name", "city_name", "org_name", "event_name",
    "report_name", "as_name", "observable_value", "standard_id", "id",
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


__all__ = [
    "DIAMOND_QUADRANTS", "QUADRANT_TYPES", "NAME_KEYS", "summarize_relationships",
    "coverage_summary", "relationship_sample", "relationship_edges",
    "quadrant_for_object", "object_label", "object_ref", "object_summary",
    "normalize_quadrants",
]

