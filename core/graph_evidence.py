import re
from collections import Counter
from collections.abc import Mapping

from core.tlp import extract_tlp_values, normalize_tlp


GRAPH_EVIDENCE_VERSION = "v0.7.0-dev"

ENTITY_TARGETS = {
    "threat_actor": ("threat-actor", "attributed-to"),
    "intrusion_set": ("intrusion-set", "attributed-to"),
    "malware": ("malware", "uses"),
    "tool": ("tool", "uses"),
    "vulnerability": ("vulnerability", "related-to"),
    "attack_pattern": ("attack-pattern", "uses"),
    "attack_tactic": ("x-mitre-tactic", "uses"),
    "target_sector": ("identity", "targets"),
    "target_country": ("location", "targets"),
    "target_region": ("location", "targets"),
    "source_identity": ("identity", "originated-from"),
    "collector": ("identity", "collected-by"),
    "tag": ("label", "labels"),
    "marking": ("marking-definition", "marked-with"),
    "external_reference": ("external-reference", "references"),
    "attack_platform": ("x-narrowcti-attack-platform", "applies-to"),
    "attack_data_source": ("x-mitre-data-source", "detects"),
    "detection_guidance": ("note", "documents"),
    "event_report": ("note", "documents"),
}

ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def build_graph_evidence(metadata, source_key="", external_id="", title=""):
    metadata = metadata if isinstance(metadata, Mapping) else {}
    records = []
    records.extend(otx_entity_evidence(metadata.get("otx_entities"), source_key))
    records.extend(mitre_attack_evidence(metadata.get("mitre_attack"), source_key))
    records.extend(misp_metadata_evidence(metadata, source_key))
    records.extend(misp_galaxy_evidence(metadata.get("misp_galaxies"), source_key))
    records.extend(
        misp_vulnerability_evidence(metadata.get("misp_vulnerabilities"), source_key)
    )
    records.extend(
        misp_event_report_evidence(metadata.get("misp_event_reports"), source_key)
    )

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
            display_name=item.get("display_name"),
            attributes=item.get("attributes"),
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
        tactics = clean_values(technique.get("tactics"))
        platforms = clean_values(technique.get("platforms"))
        data_sources = clean_values(technique.get("data_sources"))
        domains = clean_values(technique.get("domains"))
        detection = clean_string(technique.get("detection"))
        url = clean_string(technique.get("url"))
        external_references = mitre_external_references(attack_id, url)
        attributes = {
            "name": name,
            "description": clean_string(technique.get("description")),
            "tactics": tactics,
            "stix_id": clean_string(technique.get("stix_id")),
            "url": url,
            "external_references": external_references,
            "kill_chain_phases": mitre_kill_chain_phases(tactics),
            "platforms": platforms,
            "data_sources": data_sources,
            "detection": detection,
            "domains": domains,
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
        if url:
            records.append(
                evidence_record(
                    entity_type="external_reference",
                    value=url,
                    source_key=source_key,
                    source_name="mitre-attack",
                    source_field="mitre_attack.resolved.url",
                    confidence=90,
                    display_name=f"MITRE ATT&CK {attack_id}",
                    attributes={
                        "source_name": "mitre-attack",
                        "external_id": attack_id,
                        "technique": attack_id,
                        "url": url,
                    },
                )
            )
        for tactic in tactics:
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
        for platform in platforms:
            platform_record = evidence_record(
                entity_type="attack_platform",
                value=platform,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.platforms",
                confidence=75,
                attributes={"technique": attack_id},
            )
            if platform_record:
                records.append(platform_record)
        for data_source in data_sources:
            data_source_record = evidence_record(
                entity_type="attack_data_source",
                value=data_source,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.data_sources",
                confidence=80,
                attributes={"technique": attack_id},
            )
            if data_source_record:
                records.append(data_source_record)
        if detection:
            records.append(
                evidence_record(
                    entity_type="detection_guidance",
                    value=detection,
                    source_key=source_key,
                    source_name="mitre-attack",
                    source_field="mitre_attack.resolved.detection",
                    confidence=70,
                    display_name=f"Detection guidance for {attack_id}",
                    attributes={"technique": attack_id},
                )
            )
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


def misp_galaxy_evidence(clusters, source_key=""):
    records = []
    for cluster in clusters or []:
        if not isinstance(cluster, Mapping):
            continue
        entity_type, confidence = classify_misp_galaxy(cluster)
        if not entity_type:
            continue
        value = misp_galaxy_value(entity_type, cluster)
        attributes = misp_galaxy_attributes(cluster)
        record = evidence_record(
            entity_type=entity_type,
            value=value,
            source_key=source_key,
            source_name="misp-galaxy",
            source_field=cluster.get("source_field") or "misp_galaxies",
            confidence=confidence,
            display_name=cluster.get("value"),
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def classify_misp_galaxy(cluster):
    kind = " ".join(
        clean_string(cluster.get(field)).casefold()
        for field in ("type", "galaxy_type", "galaxy_name", "tag_name")
        if clean_string(cluster.get(field))
    )
    if not kind:
        return "", 0
    if "attack-pattern" in kind or "mitre-attack-pattern" in kind:
        return "attack_pattern", 85
    if "intrusion-set" in kind:
        return "intrusion_set", 80
    if "vulnerability" in kind or "cve" in kind:
        return "vulnerability", 80
    if "threat-actor" in kind or "threat actor" in kind:
        return "threat_actor", 80
    if "malpedia" in kind or "ransomware" in kind or "malware" in kind:
        return "malware", 80
    if "tool" in kind:
        return "tool", 75
    if "sector" in kind:
        return "target_sector", 70
    if "country" in kind:
        return "target_country", 70
    if "region" in kind:
        return "target_region", 65
    return "", 0


def misp_galaxy_value(entity_type, cluster):
    if entity_type == "attack_pattern":
        attack_id = first_attack_id_from_cluster(cluster)
        if attack_id:
            return attack_id
    if entity_type == "vulnerability":
        cve_id = first_cve_id_from_cluster(cluster)
        if cve_id:
            return cve_id
    return clean_string(cluster.get("value"))


def first_attack_id_from_cluster(cluster):
    values = [
        cluster.get("value"),
        cluster.get("tag_name"),
        cluster.get("description"),
    ]
    meta = compact_mapping(cluster.get("meta"))
    for key in ("external_id", "external-id", "mitre_id", "mitre-id", "id", "refs"):
        values.extend(flatten_values(meta.get(key)))
    for value in values:
        match = ATTACK_ID_PATTERN.search(clean_string(value))
        if match:
            return match.group(0).upper()
    return ""


def first_cve_id_from_cluster(cluster):
    values = [
        cluster.get("value"),
        cluster.get("tag_name"),
        cluster.get("description"),
    ]
    meta = compact_mapping(cluster.get("meta"))
    for key in ("external_id", "external-id", "cve", "cves", "id", "refs"):
        values.extend(flatten_values(meta.get(key)))
    for value in values:
        match = CVE_ID_PATTERN.search(clean_string(value))
        if match:
            return match.group(0).upper()
    return ""


def misp_galaxy_attributes(cluster):
    meta = compact_mapping(cluster.get("meta"))
    attributes = {
        "galaxy_type": clean_string(cluster.get("galaxy_type")),
        "galaxy_name": clean_string(cluster.get("galaxy_name")),
        "cluster_type": clean_string(cluster.get("type")),
        "cluster_uuid": clean_string(cluster.get("uuid")),
        "tag_name": clean_string(cluster.get("tag_name")),
        "description": clean_string(cluster.get("description")),
        "meta": meta,
    }
    attack_id = first_attack_id_from_cluster(cluster)
    if attack_id:
        attributes["external_id"] = attack_id
    cve_id = first_cve_id_from_cluster(cluster)
    if cve_id:
        attributes["external_id"] = cve_id
    return compact_mapping(attributes)


def misp_vulnerability_evidence(vulnerabilities, source_key=""):
    records = []
    for vulnerability in vulnerabilities or []:
        vulnerability = compact_mapping(vulnerability)
        if not vulnerability:
            continue
        attributes = compact_mapping(
            {
                "source_type": vulnerability.get("source_type"),
                "attribute_type": vulnerability.get("attribute_type"),
                "attribute_category": vulnerability.get("attribute_category"),
                "attribute_uuid": vulnerability.get("attribute_uuid"),
                "object_name": vulnerability.get("object_name"),
                "object_uuid": vulnerability.get("object_uuid"),
                "tags": vulnerability.get("tags"),
            }
        )
        record = evidence_record(
            entity_type="vulnerability",
            value=vulnerability.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=vulnerability.get("source_field"),
            confidence=75,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def misp_event_report_evidence(event_reports, source_key=""):
    records = []
    for event_report in event_reports or []:
        event_report = compact_mapping(event_report)
        if not event_report:
            continue
        title = clean_string(event_report.get("title"))
        content = clean_string(event_report.get("content"))
        value = title or content[:120]
        attributes = compact_mapping(
            {
                "content": content,
                "event_report_uuid": event_report.get("uuid"),
                "timestamp": event_report.get("timestamp"),
                "created": event_report.get("created"),
                "modified": event_report.get("modified"),
            }
        )
        record = evidence_record(
            entity_type="event_report",
            value=value,
            source_key=source_key,
            source_name="misp",
            source_field=event_report.get("source_field") or "EventReport",
            confidence=70,
            display_name=title,
            attributes=attributes,
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


def clean_values(values):
    return [clean_string(value) for value in values or [] if clean_string(value)]


def flatten_values(value):
    if isinstance(value, Mapping):
        flattened = []
        for item in value.values():
            flattened.extend(flatten_values(item))
        return flattened
    if isinstance(value, (list, tuple, set)):
        flattened = []
        for item in value:
            flattened.extend(flatten_values(item))
        return flattened
    return [value] if value not in ("", None, [], {}) else []


def mitre_external_references(attack_id, url):
    if not attack_id and not url:
        return []
    reference = {"source_name": "mitre-attack"}
    if attack_id:
        reference["external_id"] = attack_id
    if url:
        reference["url"] = url
    return [reference]


def mitre_kill_chain_phases(tactics):
    return [
        {"kill_chain_name": "mitre-attack", "phase_name": tactic}
        for tactic in tactics or []
        if clean_string(tactic)
    ]


def clamp_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))
