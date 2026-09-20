# ruff: noqa: F401,F403,F405
from collections.abc import Mapping
from .common import *  # noqa: F403,F401
from .misp_relationships import MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES

MISP_GALAXY_TAG_PATTERN = re.compile(
    r'^misp-galaxy:([^=]+)=(?:"([^"]+)"|(.+))$',
    re.IGNORECASE,
)

MISP_GALAXY_CONTEXT_ANCHOR_ENTITY_TYPES = {
    "attack_pattern",
    "channel",
    "infrastructure",
    "malware",
    "tool",
} | MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES

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
            "cfr-target-category",
            "cfr-target-categories",
            "cfr_target_category",
            "cfr_target_categories",
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
            "cfr-suspected-victim",
            "cfr-suspected-victims",
            "cfr_suspected_victim",
            "cfr_suspected_victims",
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
            "observed-motivation",
            "observed-motivations",
            "observed_motivation",
            "observed_motivations",
            "cfr-type-of-incident",
            "cfr-types-of-incident",
            "cfr_type_of_incident",
            "cfr_types_of_incident",
            "type-of-incident",
            "types-of-incident",
            "type_of_incident",
            "types_of_incident",
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

def misp_galaxy_tag_clusters(tags):
    clusters = []
    for index, tag in enumerate(tags or []):
        tag = clean_string(tag)
        match = MISP_GALAXY_TAG_PATTERN.match(tag)
        if not match:
            continue
        galaxy_type = clean_string(match.group(1))
        value = clean_string(match.group(2) or match.group(3))
        if not galaxy_type or not value:
            continue
        clusters.append(
            {
                "type": galaxy_type,
                "galaxy_type": galaxy_type,
                "galaxy_name": galaxy_type,
                "tag_name": tag,
                "value": value,
                "source_field": f"tags[{index}]",
            }
        )
    return clusters

def misp_galaxy_evidence(clusters, source_key="", relationship_anchor=None):
    records = []
    for cluster in clusters or []:
        if not isinstance(cluster, Mapping):
            continue
        entity_type, confidence = classify_misp_galaxy(cluster)
        if not entity_type:
            continue
        value = misp_galaxy_value(entity_type, cluster)
        attributes = misp_galaxy_attributes(cluster, entity_type)
        if misp_galaxy_uses_context_anchor(entity_type, attributes):
            anchor = compact_mapping(relationship_anchor)
            if anchor:
                attributes.update(anchor)
        record = evidence_record(
            entity_type=entity_type,
            value=value,
            source_key=source_key,
            source_name="misp-galaxy",
            source_field=cluster.get("source_field") or "misp_galaxies",
            confidence=confidence,
            display_name=cluster.get("value"),
            relationship_type=misp_galaxy_relationship_type(entity_type, attributes),
            attributes=attributes,
        )
        if record:
            records.append(record)
        records.extend(
            misp_galaxy_meta_evidence(cluster, source_key, relationship_anchor)
        )
    return records

def misp_galaxy_uses_context_anchor(entity_type, attributes):
    if entity_type not in MISP_GALAXY_CONTEXT_ANCHOR_ENTITY_TYPES:
        return False
    attributes = compact_mapping(attributes)
    return not clean_string(attributes.get("relationship_source_value"))

def misp_galaxy_meta_evidence(cluster, source_key="", relationship_anchor=None):
    cluster = compact_mapping(cluster)
    meta = compact_mapping(cluster.get("meta"))
    if not meta:
        return []

    records = []
    anchor = misp_galaxy_meta_relationship_anchor(cluster, relationship_anchor)
    for entity_type, field_names, confidence in MISP_GALAXY_META_ENTITY_FIELDS:
        seen = set()
        for field_name in field_names:
            values = flatten_values(meta.get(field_name))
            for value in values:
                source_value = clean_string(value)
                attributes = misp_galaxy_meta_attributes(
                    cluster,
                    field_name,
                    entity_type,
                )
                if (
                    anchor
                    and entity_type in MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES
                    and not attributes.get("relationship_source_value")
                ):
                    attributes.update(anchor)
                normalized, attributes = normalize_evidence_value(
                    entity_type,
                    source_value,
                    attributes,
                )
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
                    attributes=attributes,
                )
                if record:
                    records.append(record)
    return records

def misp_galaxy_meta_relationship_anchor(cluster, relationship_anchor=None):
    cluster = compact_mapping(cluster)
    classified_entity_type, _ = classify_misp_galaxy(cluster)
    stix_object_type = {
        "campaign": "campaign",
        "intrusion_set": "intrusion-set",
        "threat_actor": "threat-actor",
    }.get(classified_entity_type)
    if stix_object_type:
        value = misp_galaxy_value(classified_entity_type, cluster)
        if value:
            return {
                "relationship_source_stix_object_type": stix_object_type,
                "relationship_source_value": value,
                "relationship_source_field": (
                    clean_string(cluster.get("source_field")) or "misp_galaxies"
                ),
            }
    return compact_mapping(relationship_anchor)

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
    if is_dotted_identifier_value(value):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    return True

def is_dotted_identifier_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not value or any(char.isspace() for char in value):
        return False
    if lowered.count(".") < 2:
        return False
    labels = lowered.split(".")
    return all(re.fullmatch(r"[a-z0-9_-]+", label or "") for label in labels)

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
                "incident-type": ("type-of-incident",),
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
    if entity_type == "course_of_action":
        attack_id, attack_source_field = first_mitigated_attack_id_from_cluster(cluster)
        if attack_id:
            attributes.update(
                {
                    "relationship_source_stix_object_type": "attack-pattern",
                    "relationship_source_value": attack_id,
                    "relationship_source_field": attack_source_field,
                }
            )
    return compact_mapping(attributes)

def misp_galaxy_relationship_type(entity_type, attributes):
    if (
        entity_type == "course_of_action"
        and clean_string(attributes.get("relationship_source_stix_object_type")).lower()
        == "attack-pattern"
        and clean_string(attributes.get("relationship_source_value"))
    ):
        return "mitigates"
    return ""

def first_mitigated_attack_id_from_cluster(cluster):
    meta = compact_mapping(cluster.get("meta"))
    for key in (
        "mitigates",
        "mitigated",
        "attack_pattern",
        "attack-pattern",
        "attack_patterns",
        "attack-patterns",
        "technique",
        "techniques",
        "related_attack_pattern",
        "related-attack-pattern",
        "related_technique",
        "related-technique",
        "mitre_attack_id",
        "mitre-attack-id",
        "mitre_technique_id",
        "mitre-technique-id",
        "refs",
    ):
        for value in flatten_values(meta.get(key)):
            match = ATTACK_ID_PATTERN.search(clean_string(value))
            if match:
                return match.group(0).upper(), f"meta.{key}"
    return "", ""

def single_misp_context_anchor(metadata):
    metadata = compact_mapping(metadata)
    anchors = misp_campaign_anchors(metadata.get("misp_campaigns"))
    galaxy_sources = list(metadata.get("misp_galaxies") or [])
    galaxy_sources.extend(misp_galaxy_tag_clusters(metadata.get("tags")))
    for entity_type, stix_object_type in (
        ("campaign", "campaign"),
        ("intrusion_set", "intrusion-set"),
        ("threat_actor", "threat-actor"),
    ):
        anchors.extend(
            misp_galaxy_anchors(
                galaxy_sources,
                entity_type,
                stix_object_type,
            )
        )
    return single_unique_anchor(anchors)

def misp_campaign_anchors(campaigns):
    anchors = []
    for campaign in campaigns or []:
        campaign = compact_mapping(campaign)
        value = clean_string(campaign.get("value"))
        if not value:
            continue
        anchors.append(
            {
                "relationship_source_stix_object_type": "campaign",
                "relationship_source_value": value,
                "relationship_source_field": (
                    clean_string(campaign.get("source_field")) or "misp_campaigns"
                ),
            }
        )
    return anchors

def misp_galaxy_anchors(clusters, entity_type, stix_object_type):
    anchors = []
    for cluster in clusters or []:
        cluster = compact_mapping(cluster)
        classified_entity_type, _ = classify_misp_galaxy(cluster)
        if classified_entity_type != entity_type:
            continue
        value = misp_galaxy_value(entity_type, cluster)
        if not value:
            continue
        anchors.append(
            {
                "relationship_source_stix_object_type": stix_object_type,
                "relationship_source_value": value,
                "relationship_source_field": (
                    clean_string(cluster.get("source_field")) or "misp_galaxies"
                ),
            }
        )
    return anchors

def single_unique_anchor(anchors):
    unique = {}
    for anchor in anchors:
        anchor = compact_mapping(anchor)
        key = (
            clean_string(anchor.get("relationship_source_stix_object_type")).casefold(),
            clean_string(anchor.get("relationship_source_value")).casefold(),
        )
        if not all(key):
            continue
        unique[key] = anchor
    if len(unique) != 1:
        return {}
    return next(iter(unique.values()))
