from collections import Counter
from collections.abc import Mapping

from core.tlp import extract_tlp_values, normalize_tlp


GRAPH_EVIDENCE_VERSION = "v0.7.0-dev"

ENTITY_TARGETS = {
    "threat_actor": ("threat-actor", "attributed-to"),
    "malware": ("malware", "uses"),
    "tool": ("tool", "uses"),
    "attack_pattern": ("attack-pattern", "uses"),
    "attack_tactic": ("x-mitre-tactic", "uses"),
    "target_sector": ("identity", "targets"),
    "target_country": ("location", "targets"),
    "source_identity": ("identity", "originated-from"),
    "collector": ("identity", "collected-by"),
    "tag": ("label", "labels"),
    "marking": ("marking-definition", "marked-with"),
    "external_reference": ("external-reference", "references"),
}


def build_graph_evidence(metadata, source_key="", external_id="", title=""):
    metadata = metadata if isinstance(metadata, Mapping) else {}
    records = []
    records.extend(otx_entity_evidence(metadata.get("otx_entities"), source_key))
    records.extend(mitre_attack_evidence(metadata.get("mitre_attack"), source_key))
    records.extend(misp_metadata_evidence(metadata, source_key))

    return {
        "version": GRAPH_EVIDENCE_VERSION,
        "source_key": clean_string(source_key),
        "external_id": clean_string(external_id),
        "title": clean_string(title),
        "record_count": len(records),
        "counts": dict(
            sorted(Counter(record["entity_type"] for record in records).items())
        ),
        "records": records,
    }


def otx_entity_evidence(entities, source_key=""):
    if not isinstance(entities, Mapping):
        return []
    records = []
    for item in entities.get("records") or []:
        if not isinstance(item, Mapping):
            continue
        record = evidence_record(
            entity_type=item.get("entity_type"),
            value=item.get("value"),
            source_key=source_key,
            source_name="otx",
            source_field=item.get("source_field"),
            confidence=item.get("confidence"),
        )
        if record:
            records.append(record)
    return records


def mitre_attack_evidence(mitre_attack, source_key=""):
    if not isinstance(mitre_attack, Mapping) or not mitre_attack.get("available"):
        return []
    records = []
    for technique in mitre_attack.get("resolved") or []:
        if not isinstance(technique, Mapping) or not technique.get("found"):
            continue
        attack_id = clean_string(technique.get("attack_id"))
        name = clean_string(technique.get("name"))
        attributes = {
            "name": name,
            "description": clean_string(technique.get("description")),
            "tactics": list(technique.get("tactics") or []),
            "stix_id": clean_string(technique.get("stix_id")),
            "url": clean_string(technique.get("url")),
            "platforms": list(technique.get("platforms") or []),
            "data_sources": list(technique.get("data_sources") or []),
            "detection": clean_string(technique.get("detection")),
            "domains": list(technique.get("domains") or []),
            "version": clean_string(technique.get("version")),
            "attack_spec_version": clean_string(
                technique.get("attack_spec_version")
            ),
            "created": clean_string(technique.get("created")),
            "modified": clean_string(technique.get("modified")),
            "is_subtechnique": bool(technique.get("is_subtechnique", False)),
            "revoked": bool(technique.get("revoked", False)),
            "deprecated": bool(technique.get("deprecated", False)),
        }
        record = evidence_record(
            entity_type="attack_pattern",
            value=attack_id,
            source_key=source_key,
            source_name=clean_string(technique.get("source_name")) or "mitre-attack",
            source_field="mitre_attack.resolved",
            confidence=90,
            display_name=name,
            attributes=attributes,
        )
        if record:
            records.append(record)
        for tactic in attributes["tactics"]:
            tactic_record = evidence_record(
                entity_type="attack_tactic",
                value=tactic,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.tactics",
                confidence=85,
                attributes={"technique": attack_id},
            )
            if tactic_record:
                records.append(tactic_record)
    return records


def misp_metadata_evidence(metadata, source_key=""):
    if not isinstance(metadata, Mapping):
        return []
    records = []
    collector = evidence_record(
        entity_type="collector",
        value=metadata.get("collector"),
        source_key=source_key,
        source_name="misp",
        source_field="provenance.collector",
        confidence=80,
    )
    if collector:
        records.append(collector)

    original_source = evidence_record(
        entity_type="source_identity",
        value=metadata.get("original_source"),
        source_key=source_key,
        source_name="misp",
        source_field="provenance.original_source",
        confidence=70,
    )
    if original_source:
        records.append(original_source)

    tags = list(metadata.get("tags") or [])
    tlp_values = set(extract_tlp_values(tags))
    for value in sorted(tlp_values):
        record = evidence_record(
            entity_type="marking",
            value=value,
            source_key=source_key,
            source_name="misp",
            source_field="tags",
            confidence=80,
        )
        if record:
            records.append(record)

    for tag in tags:
        normalized_tag = clean_string(tag).lower()
        is_tlp_tag = normalized_tag.startswith("tlp:")
        if is_tlp_tag and normalize_tlp(tag) in tlp_values:
            continue
        record = evidence_record(
            entity_type="tag",
            value=tag,
            source_key=source_key,
            source_name="misp",
            source_field="tags",
            confidence=35,
        )
        if record:
            records.append(record)

    return records


def evidence_record(
    entity_type,
    value,
    source_key="",
    source_name="",
    source_field="",
    confidence=50,
    display_name="",
    attributes=None,
):
    entity_type = clean_string(entity_type)
    value = clean_string(value)
    if not entity_type or not value:
        return {}

    stix_object_type, relationship_type = ENTITY_TARGETS.get(
        entity_type,
        ("x-narrowcti-evidence", "related-to"),
    )
    record = {
        "entity_type": entity_type,
        "value": value,
        "stix_object_type": stix_object_type,
        "relationship_type": relationship_type,
        "source_key": clean_string(source_key),
        "source_name": clean_string(source_name),
        "source_field": clean_string(source_field),
        "confidence": clamp_confidence(confidence),
    }
    display_name = clean_string(display_name)
    if display_name and display_name != value:
        record["display_name"] = display_name
    compact_attributes = compact_mapping(attributes)
    if compact_attributes:
        record["attributes"] = compact_attributes
    return record


def compact_mapping(value):
    if not isinstance(value, Mapping):
        return {}
    return {
        clean_string(key): item
        for key, item in value.items()
        if clean_string(key) and item not in ("", None, [], {})
    }


def clean_string(value):
    return " ".join(str(value or "").strip().split())


def clamp_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))
