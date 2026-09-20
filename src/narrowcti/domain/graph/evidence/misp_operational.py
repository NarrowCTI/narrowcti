from .common import (
    clean_string,
    compact_mapping,
    evidence_record,
    first_confidence_value,
    normalize_evidence_value,
)
from .misp_contracts import is_safe_misp_meta_graph_value

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
                "first_seen": vulnerability.get("first_seen"),
                "last_seen": vulnerability.get("last_seen"),
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

def misp_campaign_evidence(campaigns, source_key=""):
    records = []
    for campaign in campaigns or []:
        campaign = compact_mapping(campaign)
        if not campaign:
            continue
        attributes = compact_mapping(
            {
                "source_type": campaign.get("source_type"),
                "attribute_type": campaign.get("attribute_type"),
                "attribute_category": campaign.get("attribute_category"),
                "attribute_uuid": campaign.get("attribute_uuid"),
                "attribute_relation": campaign.get("attribute_relation"),
                "first_seen": campaign.get("first_seen"),
                "last_seen": campaign.get("last_seen"),
                "object_name": campaign.get("object_name"),
                "object_uuid": campaign.get("object_uuid"),
                "object_meta_category": campaign.get("object_meta_category"),
                "tags": campaign.get("tags"),
            }
        )
        record = evidence_record(
            entity_type="campaign",
            value=campaign.get("value"),
            source_key=source_key,
            source_name="misp",
            source_field=campaign.get("source_field"),
            confidence=70,
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records

def misp_victimology_evidence(victimology_records, source_key="", relationship_anchor=None):
    records = []
    for item in victimology_records or []:
        item = compact_mapping(item)
        entity_type = clean_string(item.get("entity_type"))
        value = clean_string(item.get("value"))
        if not entity_type or not value:
            continue
        attributes = compact_mapping(
            {
                "source_type": item.get("source_type"),
                "attribute_type": item.get("attribute_type"),
                "attribute_category": item.get("attribute_category"),
                "attribute_uuid": item.get("attribute_uuid"),
                "attribute_relation": item.get("attribute_relation"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "object_name": item.get("object_name"),
                "object_uuid": item.get("object_uuid"),
                "object_meta_category": item.get("object_meta_category"),
                "tags": item.get("tags"),
            }
        )
        anchor = compact_mapping(relationship_anchor)
        if anchor and not attributes.get("relationship_source_value"):
            attributes.update(anchor)
        normalized, attributes = normalize_evidence_value(
            entity_type,
            value,
            attributes,
        )
        if not normalized or not is_safe_misp_meta_graph_value(entity_type, normalized):
            continue
        record = evidence_record(
            entity_type=entity_type,
            value=normalized,
            source_key=source_key,
            source_name="misp-attribute",
            source_field=item.get("source_field") or "Attribute",
            confidence=item.get("confidence") or 65,
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
                "confidence": sighting.get("confidence"),
                "source_confidence": sighting.get("source_confidence"),
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
            confidence=misp_sighting_confidence(sighting),
            attributes=attributes,
        )
        if record:
            records.append(record)
    return records

def misp_sighting_confidence(sighting):
    return first_confidence_value(
        sighting.get("confidence"),
        sighting.get("source_confidence"),
        65,
    )

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
