from collections.abc import Mapping

from narrowcti.domain.intelligence.tlp import extract_tlp_values, normalize_tlp

from .common import clean_string, compact_mapping, evidence_record
from .misp_galaxy import misp_galaxy_evidence, misp_galaxy_tag_clusters

def with_default_timeline(records, timeline_attributes):
    timeline_attributes = compact_mapping(timeline_attributes)
    if not timeline_attributes:
        return list(records or [])
    enriched = []
    for record in records or []:
        if not isinstance(record, Mapping):
            continue
        merged = dict(record)
        attributes = {
            **timeline_attributes,
            **compact_mapping(record.get("attributes")),
        }
        if attributes:
            merged["attributes"] = attributes
        enriched.append(merged)
    return enriched

def misp_timeline_attributes(metadata):
    return compact_mapping(
        {
            "source_created": metadata.get("misp_event_created"),
            "source_timestamp": metadata.get("misp_event_timestamp"),
            "source_date": metadata.get("misp_event_date"),
        }
    )

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

    records.extend(misp_galaxy_evidence(misp_galaxy_tag_clusters(tags), source_key))

    return records
