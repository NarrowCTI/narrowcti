from __future__ import annotations

import re
from collections.abc import Mapping

from ._common import (
    attribute_tags,
    clean_text,
    compact_mapping,
    flatten_text,
    is_truthy,
    list_values,
)



CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

MISP_VICTIMOLOGY_ATTRIBUTE_TYPES = {
    "target-org": ("target_organization", 68),
    "target-machine": ("target_system", 65),
    "target-location": ("target_country", 70),
}



def extract_misp_galaxies(event):
    event = compact_mapping(event)
    clusters = []
    for container in misp_galaxy_containers(event):
        galaxy = compact_mapping(container.get("galaxy"))
        for cluster in container.get("clusters") or []:
            normalized = normalize_misp_galaxy_cluster(
                cluster,
                galaxy,
                container.get("source_field", "Galaxy"),
            )
            if normalized:
                clusters.append(normalized)
    return deduplicate_misp_galaxies(clusters)

def misp_galaxy_containers(event):
    containers = []
    containers.extend(galaxy_containers_from_mapping(event, "Galaxy"))
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        if isinstance(attribute, Mapping):
            containers.extend(
                galaxy_containers_from_mapping(attribute, f"Attribute[{index}].Galaxy")
            )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        if not isinstance(misp_object, Mapping):
            continue
        containers.extend(
            galaxy_containers_from_mapping(misp_object, f"Object[{object_index}].Galaxy")
        )
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            if isinstance(attribute, Mapping):
                containers.extend(
                    galaxy_containers_from_mapping(
                        attribute,
                        f"Object[{object_index}].Attribute[{attribute_index}].Galaxy",
                    )
                )
    return containers

def galaxy_containers_from_mapping(value, source_field):
    value = compact_mapping(value)
    containers = []
    for galaxy in list_values(value.get("Galaxy")):
        galaxy = compact_mapping(galaxy)
        clusters = list_values(
            galaxy.get("GalaxyCluster") or galaxy.get("GalaxyClusters")
        )
        if clusters:
            containers.append(
                {
                    "galaxy": galaxy,
                    "clusters": clusters,
                    "source_field": source_field,
                }
            )
    direct_clusters = list_values(
        value.get("GalaxyCluster") or value.get("GalaxyClusters")
    )
    if direct_clusters:
        containers.append(
            {
                "galaxy": {},
                "clusters": direct_clusters,
                "source_field": source_field.replace("Galaxy", "GalaxyCluster"),
            }
        )
    return containers

def normalize_misp_galaxy_cluster(cluster, galaxy, source_field):
    cluster = compact_mapping(cluster)
    if not cluster:
        return {}
    galaxy = compact_mapping(galaxy)
    meta = compact_mapping(cluster.get("meta"))
    value = (
        cluster.get("value")
        or cluster.get("name")
        or cluster.get("tag_name")
        or cluster.get("uuid")
        or ""
    )
    if not value:
        return {}
    return {
        "value": value,
        "type": cluster.get("type") or galaxy.get("type") or galaxy.get("name") or "",
        "description": cluster.get("description", ""),
        "uuid": cluster.get("uuid", ""),
        "tag_name": cluster.get("tag_name", ""),
        "galaxy_type": galaxy.get("type", ""),
        "galaxy_name": galaxy.get("name", ""),
        "source_field": source_field,
        "meta": meta,
    }

def deduplicate_misp_galaxies(clusters):
    seen = set()
    deduplicated = []
    for cluster in clusters:
        key = (
            str(cluster.get("type", "")).casefold(),
            str(cluster.get("value", "")).casefold(),
            str(cluster.get("uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(cluster)
    return deduplicated

def extract_misp_vulnerabilities(event, tags=None):
    findings = []
    for source in misp_vulnerability_sources(event, tags or []):
        for cve_id in normalize_cve_ids(source.get("value")):
            findings.append(
                compact_mapping(
                    {
                        "value": cve_id,
                        "source_field": source.get("source_field"),
                        "source_type": source.get("source_type"),
                        "attribute_type": source.get("attribute_type"),
                        "attribute_category": source.get("attribute_category"),
                        "attribute_uuid": source.get("attribute_uuid"),
                        "first_seen": source.get("first_seen"),
                        "last_seen": source.get("last_seen"),
                        "object_name": source.get("object_name"),
                        "object_uuid": source.get("object_uuid"),
                        "tags": source.get("tags"),
                    }
                )
            )
    return deduplicate_misp_vulnerabilities(findings)

def extract_misp_campaigns(event):
    event = compact_mapping(event)
    campaigns = []
    for source in misp_campaign_sources(event):
        normalized = normalize_misp_campaign(source)
        if normalized:
            campaigns.append(normalized)
    return deduplicate_misp_campaigns(campaigns)

def misp_campaign_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
                "source_type": "attribute",
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                    "source_type": "object-attribute",
                }
            )
    return sources

def normalize_misp_campaign(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    if not is_explicit_misp_campaign_source(attribute, misp_object):
        return {}
    value = clean_text(
        attribute.get("value")
        or attribute.get("comment")
        or attribute.get("uuid")
    )
    if not is_safe_misp_campaign_value(value):
        return {}
    return compact_mapping(
        {
            "value": value,
            "source_type": source.get("source_type"),
            "source_field": source.get("source_field"),
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "attribute_relation": attribute.get("object_relation"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "object_meta_category": misp_object.get("meta-category"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )

def is_explicit_misp_campaign_source(attribute, misp_object):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    object_name = clean_text(misp_object.get("name")).casefold()
    relation = clean_text(attribute.get("object_relation")).casefold()
    attribute_type = clean_text(attribute.get("type")).casefold()
    category = clean_text(attribute.get("category")).casefold()
    explicit_terms = {
        "campaign",
        "campaign-name",
        "operation",
        "operation-name",
        "threat-campaign",
    }
    object_is_campaign = object_name in explicit_terms or object_name.endswith(
        "-campaign"
    )
    relation_is_campaign = relation in explicit_terms or relation.endswith(
        "-campaign"
    )
    type_is_campaign = attribute_type in explicit_terms
    category_is_campaign = category in {"attribution", "external analysis"}
    return type_is_campaign or relation_is_campaign or (
        object_is_campaign and category_is_campaign
    )

def is_safe_misp_campaign_value(value):
    value = clean_text(value)
    lowered = value.casefold()
    if not value:
        return False
    if lowered.startswith(("http://", "https://", "ftp://", "tlp:")):
        return False
    if "@" in value and not any(char.isspace() for char in value):
        return False
    if CVE_ID_PATTERN.fullmatch(value):
        return False
    if re.fullmatch(r"\bT\d{4}(?:\.\d{3})?\b", value, re.IGNORECASE):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    if re.fullmatch(r"\d+", value):
        return False
    return True

def deduplicate_misp_campaigns(campaigns):
    seen = set()
    deduplicated = []
    for campaign in campaigns:
        key = (
            str(campaign.get("value", "")).casefold(),
            str(campaign.get("attribute_uuid", "")).casefold(),
            str(campaign.get("object_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(campaign)
    return deduplicated

def extract_misp_victimology(event):
    event = compact_mapping(event)
    records = []
    for source in misp_attribute_sources(event):
        normalized = normalize_misp_victimology(source)
        if normalized:
            records.append(normalized)
    return deduplicate_misp_victimology(records)

def misp_attribute_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
                "source_type": "attribute",
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                    "source_type": "object-attribute",
                }
            )
    return sources

def normalize_misp_victimology(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    entity_type, confidence = misp_victimology_entity_type(attribute)
    if not entity_type:
        return {}
    value = clean_text(attribute.get("value") or attribute.get("comment"))
    if not value:
        return {}
    return compact_mapping(
        {
            "value": value,
            "entity_type": entity_type,
            "confidence": confidence,
            "source_type": source.get("source_type"),
            "source_field": source.get("source_field"),
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "attribute_relation": attribute.get("object_relation"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "object_meta_category": misp_object.get("meta-category"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )

def misp_victimology_entity_type(attribute):
    attribute = compact_mapping(attribute)
    attribute_type = clean_text(attribute.get("type")).casefold()
    relation = clean_text(attribute.get("object_relation")).casefold()
    return (
        MISP_VICTIMOLOGY_ATTRIBUTE_TYPES.get(attribute_type)
        or MISP_VICTIMOLOGY_ATTRIBUTE_TYPES.get(relation)
        or ("", 0)
    )

def deduplicate_misp_victimology(records):
    seen = set()
    deduplicated = []
    for record in records:
        key = (
            str(record.get("entity_type", "")).casefold(),
            str(record.get("value", "")).casefold(),
            str(record.get("attribute_uuid", "")).casefold(),
            str(record.get("object_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(record)
    return deduplicated

def misp_vulnerability_sources(event, tags):
    event = compact_mapping(event)
    sources = []
    for index, tag in enumerate(tags or []):
        sources.append(
            {
                "value": tag,
                "source_field": f"tags[{index}]",
                "source_type": "tag",
            }
        )
    for field in ("info", "name", "description"):
        sources.append(
            {
                "value": event.get(field),
                "source_field": field,
                "source_type": "event",
            }
        )
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        if isinstance(attribute, Mapping):
            sources.append(
                misp_attribute_vulnerability_source(
                    attribute,
                    f"Attribute[{index}]",
                )
            )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        if not isinstance(misp_object, Mapping):
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            if isinstance(attribute, Mapping):
                sources.append(
                    misp_attribute_vulnerability_source(
                        attribute,
                        f"Object[{object_index}].Attribute[{attribute_index}]",
                        misp_object=misp_object,
                    )
                )
    return sources

def misp_attribute_vulnerability_source(attribute, source_field, misp_object=None):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    return compact_mapping(
        {
            "value": attribute.get("value"),
            "source_field": source_field,
            "source_type": "attribute",
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )

def normalize_cve_ids(value):
    cve_ids = []
    for item in flatten_text(value):
        for match in CVE_ID_PATTERN.findall(str(item or "")):
            normalized = match.upper()
            if normalized not in cve_ids:
                cve_ids.append(normalized)
    return cve_ids

def deduplicate_misp_vulnerabilities(findings):
    seen = set()
    deduplicated = []
    for finding in findings:
        key = str(finding.get("value", "")).casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated

def extract_misp_event_reports(event):
    event = compact_mapping(event)
    reports = []
    for index, report in enumerate(list_values(event.get("EventReport"))):
        normalized = normalize_misp_event_report(report, f"EventReport[{index}]")
        if normalized:
            reports.append(normalized)
    return deduplicate_misp_event_reports(reports)

def normalize_misp_event_report(report, source_field):
    report = compact_mapping(report)
    if not report or is_truthy(report.get("deleted")):
        return {}
    title = clean_text(
        report.get("name")
        or report.get("title")
        or report.get("event_report_title")
        or report.get("uuid")
    )
    content = clean_text(
        report.get("content")
        or report.get("text")
        or report.get("body")
        or report.get("value")
    )
    if not title and content:
        title = content[:120]
    if not title and not content:
        return {}
    return compact_mapping(
        {
            "title": title,
            "content": content,
            "uuid": report.get("uuid"),
            "timestamp": report.get("timestamp"),
            "created": report.get("created"),
            "modified": report.get("modified"),
            "source_field": source_field,
        }
    )

def deduplicate_misp_event_reports(reports):
    seen = set()
    deduplicated = []
    for report in reports:
        key = (
            str(report.get("uuid", "")).casefold(),
            str(report.get("title", "")).casefold(),
            str(report.get("content", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(report)
    return deduplicated

def extract_misp_sightings(event):
    event = compact_mapping(event)
    sightings = []
    for source in misp_sighting_sources(event):
        for index, sighting in enumerate(list_values(source.get("sightings"))):
            normalized = normalize_misp_sighting(
                sighting,
                source,
                f"{source.get('source_field')}.Sighting[{index}]",
            )
            if normalized:
                sightings.append(normalized)
    return deduplicate_misp_sightings(sightings)

def misp_sighting_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "sightings": attribute.get("Sighting"),
                "attribute_type": attribute.get("type"),
                "attribute_category": attribute.get("category"),
                "attribute_value": attribute.get("value"),
                "attribute_uuid": attribute.get("uuid"),
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "sightings": attribute.get("Sighting"),
                    "attribute_type": attribute.get("type"),
                    "attribute_category": attribute.get("category"),
                    "attribute_value": attribute.get("value"),
                    "attribute_uuid": attribute.get("uuid"),
                    "object_name": misp_object.get("name"),
                    "object_uuid": misp_object.get("uuid"),
                }
            )
    return sources

def normalize_misp_sighting(sighting, source, source_field):
    sighting = compact_mapping(sighting)
    source = compact_mapping(source)
    if not sighting or is_truthy(sighting.get("deleted")):
        return {}
    observed_value = clean_text(
        source.get("attribute_value")
        or sighting.get("value")
        or sighting.get("uuid")
        or sighting.get("id")
    )
    if not observed_value:
        return {}
    organization = compact_mapping(
        sighting.get("Organisation") or sighting.get("Organization")
    )
    return compact_mapping(
        {
            "value": observed_value,
            "sighting_id": sighting.get("id"),
            "sighting_uuid": sighting.get("uuid"),
            "sighting_type": sighting.get("type"),
            "date_sighting": sighting.get("date_sighting"),
            "source": sighting.get("source"),
            "confidence": sighting.get("confidence"),
            "source_confidence": sighting.get("source_confidence"),
            "organization": organization.get("name") or organization.get("uuid"),
            "organization_uuid": organization.get("uuid"),
            "attribute_type": source.get("attribute_type"),
            "attribute_category": source.get("attribute_category"),
            "attribute_uuid": source.get("attribute_uuid"),
            "object_name": source.get("object_name"),
            "object_uuid": source.get("object_uuid"),
            "source_field": source_field,
        }
    )

def deduplicate_misp_sightings(sightings):
    seen = set()
    deduplicated = []
    for sighting in sightings:
        key = (
            str(sighting.get("sighting_uuid", "")).casefold(),
            str(sighting.get("sighting_id", "")).casefold(),
            str(sighting.get("value", "")).casefold(),
            str(sighting.get("date_sighting", "")).casefold(),
            str(sighting.get("source", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(sighting)
    return deduplicated

def extract_misp_object_references(event):
    event = compact_mapping(event)
    references = []
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for reference_index, reference in enumerate(
            list_values(misp_object.get("ObjectReference"))
        ):
            normalized = normalize_misp_object_reference(
                reference,
                misp_object,
                f"Object[{object_index}].ObjectReference[{reference_index}]",
            )
            if normalized:
                references.append(normalized)
    return deduplicate_misp_object_references(references)

def normalize_misp_object_reference(reference, misp_object, source_field):
    reference = compact_mapping(reference)
    misp_object = compact_mapping(misp_object)
    if not reference or is_truthy(reference.get("deleted")):
        return {}
    source_uuid = clean_text(
        reference.get("object_uuid") or misp_object.get("uuid")
    )
    target_uuid = clean_text(
        reference.get("referenced_uuid")
        or reference.get("referenced_object_uuid")
        or reference.get("referenced_attribute_uuid")
    )
    relationship_type = normalize_misp_relationship_type(
        reference.get("relationship_type")
    )
    if not source_uuid or not target_uuid:
        return {}
    value = f"{source_uuid} {relationship_type} {target_uuid}"
    return compact_mapping(
        {
            "value": value,
            "relationship_type": relationship_type,
            "reference_id": reference.get("id"),
            "reference_uuid": reference.get("uuid"),
            "source_uuid": source_uuid,
            "source_name": misp_object.get("name"),
            "source_meta_category": misp_object.get("meta-category"),
            "target_uuid": target_uuid,
            "target_type": reference.get("referenced_type"),
            "comment": reference.get("comment"),
            "source_field": source_field,
        }
    )

def normalize_misp_relationship_type(value):
    normalized = clean_text(value).casefold().replace(" ", "-")
    return normalized or "related-to"

def deduplicate_misp_object_references(references):
    seen = set()
    deduplicated = []
    for reference in references:
        key = (
            str(reference.get("reference_uuid", "")).casefold(),
            str(reference.get("source_uuid", "")).casefold(),
            str(reference.get("relationship_type", "")).casefold(),
            str(reference.get("target_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(reference)
    return deduplicated
