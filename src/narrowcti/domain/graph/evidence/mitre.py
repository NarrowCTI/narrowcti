# ruff: noqa: F401,F403,F405
from collections.abc import Mapping
from .common import *  # noqa: F403,F401

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
                attributes=mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.tactics",
                ),
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
                attributes=mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.platforms",
                ),
            )
            if platform_record:
                records.append(platform_record)
        for data_source in data_sources:
            data_component = mitre_data_component_from_data_source(data_source)
            data_source_record = evidence_record(
                entity_type="attack_data_source",
                value=data_source,
                source_key=source_key,
                source_name="mitre-attack",
                source_field="mitre_attack.resolved.data_sources",
                confidence=80,
                attributes=mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.data_sources",
                ),
            )
            if data_source_record:
                records.append(data_source_record)
            if data_component:
                component_attributes = mitre_context_attributes(
                    attack_id,
                    "mitre_attack.resolved.data_sources",
                )
                component_attributes["data_source"] = data_component["data_source"]
                component_record = evidence_record(
                    entity_type="attack_data_component",
                    value=data_component["data_component"],
                    source_key=source_key,
                    source_name="mitre-attack",
                    source_field="mitre_attack.resolved.data_sources",
                    confidence=78,
                    attributes=component_attributes,
                )
                if component_record:
                    records.append(component_record)
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
                    attributes=mitre_context_attributes(
                        attack_id,
                        "mitre_attack.resolved.detection",
                    ),
                )
            )
    return records

def mitre_external_references(attack_id, url):
    if not attack_id and not url:
        return []
    reference = {"source_name": "mitre-attack"}
    if attack_id:
        reference["external_id"] = attack_id
    if url:
        reference["url"] = url
    return [reference]

def mitre_context_attributes(attack_id, source_field):
    return compact_mapping(
        {
            "technique": attack_id,
            "relationship_source_stix_object_type": "attack-pattern",
            "relationship_source_value": attack_id,
            "relationship_source_field": source_field,
        }
    )

def mitre_data_component_from_data_source(value):
    text = clean_string(value)
    if ":" not in text:
        return {}
    data_source, data_component = text.split(":", 1)
    data_source = clean_string(data_source)
    data_component = clean_string(data_component)
    if not data_source or not data_component:
        return {}
    return {
        "data_source": data_source,
        "data_component": data_component,
    }

def mitre_kill_chain_phases(tactics):
    return [
        {"kill_chain_name": "mitre-attack", "phase_name": tactic}
        for tactic in tactics or []
        if clean_string(tactic)
    ]
