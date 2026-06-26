import re
from collections import Counter
from collections.abc import Mapping

from core.tlp import extract_tlp_values, normalize_tlp


GRAPH_EVIDENCE_VERSION = "v0.7.0-dev"

ENTITY_TARGETS = {
    "campaign": ("campaign", "related-to"),
    "course_of_action": ("course-of-action", "related-to"),
    "threat_actor": ("threat-actor", "attributed-to"),
    "threat_actor_individual": ("threat-actor", "attributed-to"),
    "intrusion_set": ("intrusion-set", "attributed-to"),
    "infrastructure": ("infrastructure", "uses"),
    "autonomous_system": ("autonomous-system", "related-to"),
    "channel": ("channel", "uses"),
    "event": ("event", "related-to"),
    "malware": ("malware", "uses"),
    "narrative": ("narrative", "related-to"),
    "security_platform": ("security-platform", "related-to"),
    "tool": ("tool", "uses"),
    "vulnerability": ("vulnerability", "related-to"),
    "observable": ("observable", "based-on"),
    "attack_pattern": ("attack-pattern", "uses"),
    "attack_tactic": ("x-mitre-tactic", "uses"),
    "target_sector": ("identity", "targets"),
    "target_organization": ("identity", "targets"),
    "target_individual": ("identity", "targets"),
    "target_system": ("identity", "targets"),
    "target_administrative_area": ("location", "targets"),
    "target_city": ("location", "targets"),
    "target_country": ("location", "targets"),
    "target_position": ("location", "targets"),
    "target_region": ("location", "targets"),
    "source_identity": ("identity", "originated-from"),
    "collector": ("identity", "collected-by"),
    "tag": ("label", "labels"),
    "marking": ("marking-definition", "marked-with"),
    "external_reference": ("external-reference", "references"),
    "detection_rule": ("indicator", "detects"),
    "attack_platform": ("x-narrowcti-attack-platform", "applies-to"),
    "attack_data_source": ("x-mitre-data-source", "detects"),
    "attack_data_component": ("x-mitre-data-component", "detects"),
    "detection_guidance": ("note", "documents"),
    "event_report": ("note", "documents"),
    "sighting": ("sighting", "sighting-of"),
    "object_reference": ("relationship", "related-to"),
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
    records.extend(misp_sighting_evidence(metadata.get("misp_sightings"), source_key))
    records.extend(
        misp_object_reference_evidence(
            metadata.get("misp_object_references"),
            source_key,
        )
    )
    records.extend(
        misp_infrastructure_evidence(metadata.get("misp_infrastructure"), source_key)
    )
    records.extend(
        misp_detection_rule_evidence(metadata.get("misp_detection_rules"), source_key)
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
            stix_object_type=item.get("stix_object_type"),
            relationship_type=item.get("relationship_type"),
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
        attributes = misp_galaxy_attributes(cluster, entity_type)
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
        records.extend(misp_galaxy_meta_evidence(cluster, source_key))
    return records


def misp_galaxy_meta_evidence(cluster, source_key=""):
    cluster = compact_mapping(cluster)
    meta = compact_mapping(cluster.get("meta"))
    if not meta:
        return []

    records = []
    for entity_type, field_names, confidence in MISP_GALAXY_META_ENTITY_FIELDS:
        seen = set()
        for field_name in field_names:
            values = flatten_values(meta.get(field_name))
            for value in values:
                normalized = clean_string(value)
                key = normalized.casefold()
                if not normalized or key in seen:
                    continue
                if not is_safe_misp_meta_graph_value(entity_type, normalized):
                    continue
                seen.add(key)
                record = evidence_record(
                    entity_type=entity_type,
                    value=normalized,
                    source_key=source_key,
                    source_name="misp-galaxy",
                    source_field=meta_source_field(cluster, field_name),
                    confidence=confidence,
                    attributes=misp_galaxy_meta_attributes(
                        cluster,
                        field_name,
                        entity_type,
                    ),
                )
                if record:
                    records.append(record)
    return records


MISP_GALAXY_META_ENTITY_FIELDS = (
    (
        "target_sector",
        (
            "targeted-sector",
            "targeted-sectors",
            "targeted_sector",
            "targeted_sectors",
            "target-sector",
            "target-sectors",
            "target_sector",
            "target_sectors",
        ),
        70,
    ),
    (
        "target_country",
        (
            "targeted-country",
            "targeted-countries",
            "targeted_country",
            "targeted_countries",
            "target-country",
            "target-countries",
            "target_country",
            "target_countries",
        ),
        70,
    ),
    (
        "target_organization",
        (
            "targeted-organization",
            "targeted-organizations",
            "targeted_organization",
            "targeted_organizations",
            "targeted-org",
            "targeted-orgs",
            "target_org",
            "target_orgs",
            "targeted-company",
            "targeted-companies",
            "targeted_company",
            "targeted_companies",
            "targeted-entity",
            "targeted-entities",
            "targeted_entity",
            "targeted_entities",
            "target-organization",
            "target-organizations",
            "target_organization",
            "target_organizations",
            "target-company",
            "target-companies",
            "target_company",
            "target_companies",
            "target-entity",
            "target-entities",
            "target_entity",
            "target_entities",
            "victim-organization",
            "victim-organizations",
            "victim_organization",
            "victim_organizations",
            "victim-organization-name",
            "victim-organization-names",
            "victim_organization_name",
            "victim_organization_names",
            "victim-org",
            "victim-orgs",
            "victim_org",
            "victim_orgs",
            "victim-company",
            "victim-companies",
            "victim_company",
            "victim_companies",
            "victim-entity",
            "victim-entities",
            "victim_entity",
            "victim_entities",
            "victim",
            "victims",
            "victim-name",
            "victim-names",
            "victim_name",
            "victim_names",
            "affected-organization",
            "affected-organizations",
            "affected_organization",
            "affected_organizations",
            "affected-company",
            "affected-companies",
            "affected_company",
            "affected_companies",
            "impacted-organization",
            "impacted-organizations",
            "impacted_organization",
            "impacted_organizations",
            "impacted-company",
            "impacted-companies",
            "impacted_company",
            "impacted_companies",
        ),
        70,
    ),
    (
        "target_individual",
        (
            "targeted-individual",
            "targeted-individuals",
            "targeted_individual",
            "targeted_individuals",
            "target-individual",
            "target-individuals",
            "target_individual",
            "target_individuals",
            "targeted-person",
            "targeted-persons",
            "targeted_person",
            "targeted_persons",
            "target-person",
            "target-persons",
            "target_person",
            "target_persons",
            "victim-individual",
            "victim-individuals",
            "victim_individual",
            "victim_individuals",
            "victim-person",
            "victim-persons",
            "victim_person",
            "victim_persons",
            "affected-individual",
            "affected-individuals",
            "affected_individual",
            "affected_individuals",
            "affected-person",
            "affected-persons",
            "affected_person",
            "affected_persons",
            "impacted-individual",
            "impacted-individuals",
            "impacted_individual",
            "impacted_individuals",
            "impacted-person",
            "impacted-persons",
            "impacted_person",
            "impacted_persons",
        ),
        65,
    ),
    (
        "target_system",
        (
            "targeted-system",
            "targeted-systems",
            "targeted_system",
            "targeted_systems",
            "target-system",
            "target-systems",
            "target_system",
            "target_systems",
            "victim-system",
            "victim-systems",
            "victim_system",
            "victim_systems",
            "affected-system",
            "affected-systems",
            "affected_system",
            "affected_systems",
            "impacted-system",
            "impacted-systems",
            "impacted_system",
            "impacted_systems",
            "targeted-platform",
            "targeted-platforms",
            "targeted_platform",
            "targeted_platforms",
            "target-platform",
            "target-platforms",
            "target_platform",
            "target_platforms",
            "affected-platform",
            "affected-platforms",
            "affected_platform",
            "affected_platforms",
            "operating-system",
            "operating-systems",
            "operating_system",
            "operating_systems",
            "targeted-asset",
            "targeted-assets",
            "targeted_asset",
            "targeted_assets",
        ),
        65,
    ),
    (
        "security_platform",
        (
            "security-platform",
            "security-platforms",
            "security_platform",
            "security_platforms",
            "security-product",
            "security-products",
            "security_product",
            "security_products",
            "detection-platform",
            "detection-platforms",
            "detection_platform",
            "detection_platforms",
            "siem",
            "edr",
            "ndr",
            "xdr",
            "sensor",
            "sensors",
            "scanner",
            "scanners",
        ),
        65,
    ),
    (
        "channel",
        (
            "channel",
            "channels",
            "c2-channel",
            "c2-channels",
            "c2_channel",
            "c2_channels",
            "command-and-control-channel",
            "command-and-control-channels",
            "command_and_control_channel",
            "command_and_control_channels",
            "communication-channel",
            "communication-channels",
            "communication_channel",
            "communication_channels",
            "delivery-channel",
            "delivery-channels",
            "delivery_channel",
            "delivery_channels",
            "distribution-channel",
            "distribution-channels",
            "distribution_channel",
            "distribution_channels",
            "marketplace",
            "marketplaces",
        ),
        65,
    ),
    (
        "narrative",
        (
            "narrative",
            "narratives",
            "objective",
            "objectives",
            "campaign-objective",
            "campaign-objectives",
            "campaign_objective",
            "campaign_objectives",
            "operation-objective",
            "operation-objectives",
            "operation_objective",
            "operation_objectives",
            "motivation",
            "motivations",
            "theme",
            "themes",
            "goal",
            "goals",
            "intent",
            "intents",
        ),
        62,
    ),
    (
        "event",
        (
            "event",
            "events",
            "event-name",
            "event-names",
            "event_name",
            "event_names",
            "incident",
            "incidents",
            "incident-name",
            "incident-names",
            "incident_name",
            "incident_names",
            "observed-event",
            "observed-events",
            "observed_event",
            "observed_events",
            "activity-event",
            "activity-events",
            "activity_event",
            "activity_events",
        ),
        62,
    ),
    (
        "target_region",
        (
            "targeted-region",
            "targeted-regions",
            "targeted_region",
            "targeted_regions",
            "target-region",
            "target-regions",
            "target_region",
            "target_regions",
        ),
        65,
    ),
    (
        "target_administrative_area",
        (
            "targeted-administrative-area",
            "targeted-administrative-areas",
            "targeted_administrative_area",
            "targeted_administrative_areas",
            "target-administrative-area",
            "target-administrative-areas",
            "target_administrative_area",
            "target_administrative_areas",
            "targeted-state",
            "targeted-states",
            "targeted_state",
            "targeted_states",
            "target-state",
            "target-states",
            "target_state",
            "target_states",
            "targeted-province",
            "targeted-provinces",
            "targeted_province",
            "targeted_provinces",
            "target-province",
            "target-provinces",
            "target_province",
            "target_provinces",
        ),
        62,
    ),
    (
        "target_city",
        (
            "targeted-city",
            "targeted-cities",
            "targeted_city",
            "targeted_cities",
            "target-city",
            "target-cities",
            "target_city",
            "target_cities",
        ),
        62,
    ),
    (
        "target_position",
        (
            "targeted-position",
            "targeted-positions",
            "targeted_position",
            "targeted_positions",
            "target-position",
            "target-positions",
            "target_position",
            "target_positions",
            "targeted-coordinate",
            "targeted-coordinates",
            "targeted_coordinate",
            "targeted_coordinates",
            "target-coordinate",
            "target-coordinates",
            "target_coordinate",
            "target_coordinates",
        ),
        60,
    ),
)


TARGET_ORGANIZATION_VALUE_DENYLIST = {
    "alienvault",
    "alienvault otx",
    "misp",
    "narrowcti",
    "narrowcti gateway",
    "opencti",
    "otx",
    "the mitre corporation",
}

TARGET_INDIVIDUAL_VALUE_DENYLIST = TARGET_ORGANIZATION_VALUE_DENYLIST | {
    "admin",
    "administrator",
    "analyst",
    "author",
    "root",
    "user",
}


def is_target_organization_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not value:
        return False
    if lowered in TARGET_ORGANIZATION_VALUE_DENYLIST:
        return False
    if lowered.startswith(("http://", "https://", "ftp://", "tlp:")):
        return False
    if "@" in value and not any(char.isspace() for char in value):
        return False
    if ATTACK_ID_PATTERN.fullmatch(value) or CVE_ID_PATTERN.fullmatch(value):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    return True


def is_target_individual_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not is_target_organization_value(value):
        return False
    if lowered in TARGET_INDIVIDUAL_VALUE_DENYLIST:
        return False
    if re.fullmatch(r"\d+", value):
        return False
    return True


def is_safe_misp_meta_graph_value(entity_type, value):
    if entity_type == "target_individual":
        return is_target_individual_value(value)
    if entity_type in {
        "channel",
        "event",
        "narrative",
        "security_platform",
        "target_organization",
        "target_system",
    }:
        value = clean_string(value)
        if not is_target_organization_value(value):
            return False
        if re.fullmatch(r"\d+", value):
            return False
        return True
    return bool(clean_string(value))


def meta_source_field(cluster, field_name):
    source_field = clean_string(cluster.get("source_field")) or "Galaxy"
    return f"{source_field}.meta.{field_name}"


def misp_galaxy_meta_attributes(cluster, field_name, entity_type=""):
    attributes = compact_mapping(
        {
            "meta_key": field_name,
            "parent_galaxy_type": cluster.get("galaxy_type"),
            "parent_galaxy_name": cluster.get("galaxy_name"),
            "parent_cluster_type": cluster.get("type"),
            "parent_cluster_value": cluster.get("value"),
            "parent_cluster_uuid": cluster.get("uuid"),
            "parent_tag_name": cluster.get("tag_name"),
        }
    )
    entity_type = clean_string(entity_type)
    normalized_field = field_name.replace("_", "-").casefold()
    if entity_type == "channel":
        attributes["channel_types"] = misp_meta_context_types(
            normalized_field,
            {
                "c2": ("c2", "command-and-control"),
                "delivery": ("delivery", "distribution"),
                "communication": ("communication",),
                "marketplace": ("marketplace",),
            },
        )
    elif entity_type == "narrative":
        attributes["narrative_types"] = misp_meta_context_types(
            normalized_field,
            {
                "objective": ("objective", "goal", "intent"),
                "motivation": ("motivation",),
                "theme": ("theme", "narrative"),
            },
        )
    elif entity_type == "event":
        attributes["event_types"] = misp_meta_context_types(
            normalized_field,
            {
                "incident": ("incident",),
                "activity": ("activity", "observed"),
                "cti-event": ("event",),
            },
        )
    elif entity_type == "security_platform":
        platform_types = misp_meta_context_types(
            normalized_field,
            {
                "SIEM": ("siem",),
                "EDR": ("edr",),
                "NDR": ("ndr",),
                "XDR": ("xdr",),
                "Scanner": ("scanner",),
                "Sensor": ("sensor",),
                "Detection Platform": ("detection-platform", "security-platform"),
                "Security Product": ("security-product",),
            },
        )
        if platform_types:
            attributes["security_platform_type"] = platform_types[0]
    return compact_mapping(attributes)


def misp_meta_context_types(field_name, mapping):
    values = []
    for output, tokens in mapping.items():
        if any(token in field_name for token in tokens):
            values.append(output)
    return values


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
    if "campaign" in kind:
        return "campaign", 75
    if "course-of-action" in kind or "course of action" in kind:
        return "course_of_action", 75
    if misp_galaxy_is_threat_actor_individual(cluster, kind):
        return "threat_actor_individual", 65
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


def misp_galaxy_is_threat_actor_individual(cluster, kind=""):
    kind = kind or " ".join(
        clean_string(cluster.get(field)).casefold()
        for field in ("type", "galaxy_type", "galaxy_name", "tag_name")
        if clean_string(cluster.get(field))
    )
    normalized_kind = kind.replace("-", "").replace("_", "").replace(" ", "")
    explicit_values = []
    meta = compact_mapping(cluster.get("meta"))
    for key in (
        "actor-type",
        "actor_type",
        "threat-actor-type",
        "threat_actor_type",
        "threat-actor-class",
        "threat_actor_class",
        "type",
    ):
        explicit_values.extend(flatten_values(meta.get(key)))
    explicit = {
        clean_string(value).casefold()
        for value in explicit_values
        if clean_string(value)
    }
    return (
        "threatactorindividual" in normalized_kind
        or "threatactorsindividual" in normalized_kind
        or bool(explicit.intersection({"individual", "person", "human"}))
    )


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


def misp_galaxy_attributes(cluster, entity_type=""):
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
    if entity_type == "threat_actor":
        attributes["threat_actor_class"] = "group"
    elif entity_type == "threat_actor_individual":
        attributes["threat_actor_class"] = "individual"
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


def misp_sighting_evidence(sightings, source_key=""):
    records = []
    for sighting in sightings or []:
        sighting = compact_mapping(sighting)
        if not sighting:
            continue
        attributes = compact_mapping(
            {
                "sighting_id": sighting.get("sighting_id"),
                "sighting_uuid": sighting.get("sighting_uuid"),
                "sighting_type": sighting.get("sighting_type"),
                "date_sighting": sighting.get("date_sighting"),
                "source": sighting.get("source"),
                "organization": sighting.get("organization"),
                "organization_uuid": sighting.get("organization_uuid"),
                "attribute_type": sighting.get("attribute_type"),
                "attribute_category": sighting.get("attribute_category"),
                "attribute_uuid": sighting.get("attribute_uuid"),
                "object_name": sighting.get("object_name"),
                "object_uuid": sighting.get("object_uuid"),
            }
        )
        record = evidence_record(
            entity_type="sighting",
            value=sighting.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=sighting.get("source_field") or "Sighting",
            confidence=65,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records


def misp_object_reference_evidence(object_references, source_key=""):
    records = []
    for object_reference in object_references or []:
        object_reference = compact_mapping(object_reference)
        if not object_reference:
            continue
        attributes = compact_mapping(
            {
                "reference_id": object_reference.get("reference_id"),
                "reference_uuid": object_reference.get("reference_uuid"),
                "source_uuid": object_reference.get("source_uuid"),
                "source_name": object_reference.get("source_name"),
                "source_meta_category": object_reference.get("source_meta_category"),
                "target_uuid": object_reference.get("target_uuid"),
                "target_type": object_reference.get("target_type"),
                "comment": object_reference.get("comment"),
            }
        )
        record = evidence_record(
            entity_type="object_reference",
            value=object_reference.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=object_reference.get("source_field") or "ObjectReference",
            confidence=60,
            attributes=attributes,
            relationship_type=object_reference.get("relationship_type"),
        )
        if record:
            records.append(record)
    return records


def misp_infrastructure_evidence(infrastructure_records, source_key=""):
    records = []
    for infrastructure_record in infrastructure_records or []:
        infrastructure_record = compact_mapping(infrastructure_record)
        if not infrastructure_record:
            continue
        record = evidence_record(
            entity_type=infrastructure_record.get("entity_type"),
            value=infrastructure_record.get("value"),
            source_key=source_key,
            source_name="misp-object",
            source_field=infrastructure_record.get("source_field") or "Object",
            confidence=infrastructure_record.get("confidence", 70),
            attributes=infrastructure_record.get("attributes"),
            stix_object_type=infrastructure_record.get("stix_object_type"),
            relationship_type=infrastructure_record.get("relationship_type"),
        )
        if record:
            records.append(record)
    return records


def misp_detection_rule_evidence(detection_rules, source_key=""):
    records = []
    for detection_rule in detection_rules or []:
        detection_rule = compact_mapping(detection_rule)
        if not detection_rule:
            continue
        attributes = compact_mapping(
            {
                "rule_type": detection_rule.get("rule_type"),
                "pattern_type": detection_rule.get("pattern_type"),
                "pattern": detection_rule.get("pattern"),
                "attribute_category": detection_rule.get("attribute_category"),
                "attribute_uuid": detection_rule.get("attribute_uuid"),
                "object_name": detection_rule.get("object_name"),
                "object_uuid": detection_rule.get("object_uuid"),
                "tags": detection_rule.get("tags"),
            }
        )
        record = evidence_record(
            entity_type="detection_rule",
            value=detection_rule.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=detection_rule.get("source_field") or "Attribute",
            confidence=70,
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
    stix_object_type="",
    relationship_type="",
):
    entity_type = clean_string(entity_type)
    value = clean_string(value)
    if not entity_type or not value:
        return {}

    default_stix_object_type, default_relationship_type = ENTITY_TARGETS.get(
        entity_type,
        ("x-narrowcti-evidence", "related-to"),
    )
    stix_object_type = clean_string(stix_object_type) or default_stix_object_type
    relationship_type = clean_string(relationship_type) or default_relationship_type
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


def clamp_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))
