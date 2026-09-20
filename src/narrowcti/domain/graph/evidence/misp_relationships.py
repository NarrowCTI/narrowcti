# ruff: noqa: F401,F403,F405
from collections.abc import Mapping
from .common import *  # noqa: F403,F401

MISP_INFRA_CONTEXT_MAX_INFRASTRUCTURES = 50

MISP_INFRA_CONTEXT_MAX_PAIRINGS = 100

MISP_INFRA_CONTEXT_MAX_RECORDS = 200

MISP_INFRA_CAPABILITY_ENTITY_TYPES = {
    "malware",
    "tool",
    "channel",
}

MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES = {
    "target_administrative_area",
    "target_city",
    "target_country",
    "target_individual",
    "target_organization",
    "target_position",
    "target_region",
    "target_sector",
    "target_system",
}

MISP_CAMPAIGN_CONTEXT_MAX_CAMPAIGNS = 50

MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS = 100

MISP_CAMPAIGN_CONTEXT_MAX_RECORDS = 200

MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES = {
    "intrusion_set",
    "threat_actor",
    "threat_actor_individual",
}

MISP_CAMPAIGN_CAPABILITY_ENTITY_TYPES = {
    "attack_pattern",
    "channel",
    "malware",
    "tool",
}

def misp_infrastructure_context_relationship_evidence(records, source_key=""):
    records = [record for record in records or [] if isinstance(record, Mapping)]
    infrastructures = unique_context_records(
        (
            record
            for record in records
            if record.get("entity_type") == "infrastructure"
            and record.get("stix_object_type") == "infrastructure"
            and clean_string(record.get("source_name")).startswith("misp")
        )
    )
    if (
        not infrastructures
        or len(infrastructures) > MISP_INFRA_CONTEXT_MAX_INFRASTRUCTURES
    ):
        return []

    context_records = []
    existing = semantic_relationship_keys(records)
    actors = unique_context_records(
        record
        for record in records
        if record.get("entity_type")
        in MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(actors) == 1:
        context_records.extend(
            infrastructure_anchor_relationship_records(
                infrastructures,
                actors,
                source_key,
                existing,
                "uses",
                "misp-event-infrastructure-adversary-context",
            )
        )

    campaigns = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "campaign"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(campaigns) == 1:
        context_records.extend(
            infrastructure_anchor_relationship_records(
                infrastructures,
                campaigns,
                source_key,
                existing,
                "uses",
                "misp-event-infrastructure-campaign-context",
            )
        )

    capabilities = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_INFRA_CAPABILITY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(infrastructures) * len(capabilities) <= MISP_INFRA_CONTEXT_MAX_PAIRINGS:
        context_records.extend(
            infrastructure_anchor_relationship_records(
                infrastructures,
                capabilities,
                source_key,
                existing,
                "uses",
                "misp-event-infrastructure-capability-context",
            )
        )

    attack_patterns = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "attack_pattern"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(infrastructures) * len(attack_patterns) <= MISP_INFRA_CONTEXT_MAX_PAIRINGS:
        context_records.extend(
            infrastructure_attack_pattern_relationship_records(
                infrastructures,
                attack_patterns,
                source_key,
                existing,
            )
        )

    victimology = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if len(infrastructures) * len(victimology) <= MISP_INFRA_CONTEXT_MAX_PAIRINGS:
        context_records.extend(
            infrastructure_victimology_relationship_records(
                infrastructures,
                victimology,
                source_key,
                existing,
            )
        )

    return context_records[:MISP_INFRA_CONTEXT_MAX_RECORDS]

def misp_campaign_context_relationship_evidence(records, source_key=""):
    """Relate explicit same-event campaign context without title inference."""
    records = [record for record in records or [] if isinstance(record, Mapping)]
    campaigns = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "campaign"
        and record.get("stix_object_type") == "campaign"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        not campaigns
        or len(campaigns) > MISP_CAMPAIGN_CONTEXT_MAX_CAMPAIGNS
    ):
        return []

    existing = semantic_relationship_keys(records)
    context_records = []
    actors = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(actors) == 1
        and len(campaigns) * len(actors)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                actors,
                campaigns,
                source_key,
                existing,
                "attributed-to",
                "misp-event-campaign-adversary-context",
            )
        )

    capabilities = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_CAMPAIGN_CAPABILITY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(campaigns) * len(capabilities)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                capabilities,
                campaigns,
                source_key,
                existing,
                "uses",
                "misp-event-campaign-capability-context",
            )
        )

    infrastructures = unique_context_records(
        record
        for record in records
        if record.get("entity_type") == "infrastructure"
        and record.get("stix_object_type") == "infrastructure"
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(campaigns) * len(infrastructures)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                infrastructures,
                campaigns,
                source_key,
                existing,
                "uses",
                "misp-event-campaign-infrastructure-context",
            )
        )

    victimology = unique_context_records(
        record
        for record in records
        if record.get("entity_type") in MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES
        and clean_string(record.get("source_name")).startswith("misp")
    )
    if (
        len(campaigns) * len(victimology)
        <= MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS
    ):
        context_records.extend(
            context_anchor_relationship_records(
                victimology,
                campaigns,
                source_key,
                existing,
                "targets",
                "misp-event-campaign-victimology-context",
            )
        )

    return context_records[:MISP_CAMPAIGN_CONTEXT_MAX_RECORDS]

def infrastructure_anchor_relationship_records(
    infrastructures,
    anchors,
    source_key,
    existing,
    relationship_type,
    inference,
):
    return context_anchor_relationship_records(
        infrastructures,
        anchors,
        source_key,
        existing,
        relationship_type,
        inference,
    )

def context_anchor_relationship_records(
    targets,
    anchors,
    source_key,
    existing,
    relationship_type,
    inference,
):
    records = []
    for target in targets:
        for anchor in anchors:
            source_type = clean_string(anchor.get("stix_object_type"))
            source_value = clean_string(anchor.get("value"))
            if not source_type or not source_value:
                continue
            key = semantic_relationship_key(
                source_type,
                source_value,
                relationship_type,
                target.get("stix_object_type"),
                target.get("value"),
            )
            if key in existing:
                continue
            existing.add(key)
            attributes = {
                **compact_mapping(target.get("attributes")),
                "relationship_source_stix_object_type": source_type,
                "relationship_source_value": source_value,
                "relationship_source_field": anchor.get("source_field"),
                "relationship_inference": inference,
                "relationship_context_scope": "same-misp-event",
            }
            record = evidence_record(
                entity_type=target.get("entity_type"),
                value=target.get("value"),
                source_key=source_key,
                source_name="misp-context",
                source_field=target.get("source_field"),
                confidence=min(
                    clamp_confidence(target.get("confidence")),
                    clamp_confidence(anchor.get("confidence")),
                ),
                display_name=target.get("display_name"),
                attributes=attributes,
                stix_object_type=target.get("stix_object_type"),
                relationship_type=relationship_type,
            )
            if record:
                records.append(record)
    return records

def infrastructure_attack_pattern_relationship_records(
    infrastructures,
    attack_patterns,
    source_key,
    existing,
):
    records = []
    for infrastructure in infrastructures:
        for attack_pattern in attack_patterns:
            key = semantic_relationship_key(
                infrastructure.get("stix_object_type"),
                infrastructure.get("value"),
                "related-to",
                attack_pattern.get("stix_object_type"),
                attack_pattern.get("value"),
            )
            if key in existing:
                continue
            existing.add(key)
            attributes = {
                **compact_mapping(attack_pattern.get("attributes")),
                "relationship_source_stix_object_type": "infrastructure",
                "relationship_source_value": infrastructure.get("value"),
                "relationship_source_field": infrastructure.get("source_field"),
                "relationship_inference": "misp-event-infrastructure-ttp-context",
                "relationship_context_scope": "same-misp-event",
            }
            record = evidence_record(
                entity_type=attack_pattern.get("entity_type"),
                value=attack_pattern.get("value"),
                source_key=source_key,
                source_name="misp-context",
                source_field=attack_pattern.get("source_field"),
                confidence=min(
                    clamp_confidence(infrastructure.get("confidence")),
                    clamp_confidence(attack_pattern.get("confidence")),
                ),
                display_name=attack_pattern.get("display_name"),
                attributes=attributes,
                stix_object_type=attack_pattern.get("stix_object_type"),
                relationship_type="related-to",
            )
            if record:
                records.append(record)
    return records

def infrastructure_victimology_relationship_records(
    infrastructures,
    victimology,
    source_key,
    existing,
):
    records = []
    for infrastructure in infrastructures:
        for target in victimology:
            key = semantic_relationship_key(
                infrastructure.get("stix_object_type"),
                infrastructure.get("value"),
                "targets",
                target.get("stix_object_type"),
                target.get("value"),
            )
            if key in existing:
                continue
            existing.add(key)
            attributes = {
                **compact_mapping(target.get("attributes")),
                "relationship_source_stix_object_type": "infrastructure",
                "relationship_source_value": infrastructure.get("value"),
                "relationship_source_field": infrastructure.get("source_field"),
                "relationship_inference": "misp-event-infrastructure-victimology-context",
                "relationship_context_scope": "same-misp-event",
                "relationship_validation_state": "requires-opencti-validation",
            }
            record = evidence_record(
                entity_type=target.get("entity_type"),
                value=target.get("value"),
                source_key=source_key,
                source_name="misp-context",
                source_field=target.get("source_field"),
                confidence=min(
                    clamp_confidence(infrastructure.get("confidence")),
                    clamp_confidence(target.get("confidence")),
                ),
                display_name=target.get("display_name"),
                attributes=attributes,
                stix_object_type=target.get("stix_object_type"),
                relationship_type="targets",
            )
            if record:
                records.append(record)
    return records

def unique_context_records(records):
    unique = {}
    for record in records or []:
        record = compact_mapping(record)
        key = (
            clean_string(record.get("entity_type")).casefold(),
            clean_string(record.get("stix_object_type")).casefold(),
            clean_string(record.get("value")).casefold(),
        )
        if not all(key) or key in unique:
            continue
        unique[key] = record
    return list(unique.values())

def semantic_relationship_keys(records):
    keys = set()
    for record in records or []:
        record = compact_mapping(record)
        attributes = compact_mapping(record.get("attributes"))
        source_type = clean_string(
            attributes.get("relationship_source_stix_object_type")
        )
        source_value = clean_string(attributes.get("relationship_source_value"))
        key = semantic_relationship_key(
            source_type,
            source_value,
            record.get("relationship_type"),
            record.get("stix_object_type"),
            record.get("value"),
        )
        if key:
            keys.add(key)
    return keys

def semantic_relationship_key(
    source_type,
    source_value,
    relationship_type,
    target_type,
    target_value,
):
    values = (
        clean_string(source_type).casefold(),
        clean_string(source_value).casefold(),
        clean_string(relationship_type).casefold(),
        clean_string(target_type).casefold(),
        clean_string(target_value).casefold(),
    )
    if not all(values):
        return ()
    return values
