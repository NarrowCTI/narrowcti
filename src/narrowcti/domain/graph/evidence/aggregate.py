from collections import Counter
from collections.abc import Mapping

from .common import GRAPH_EVIDENCE_VERSION, clean_string
from .mitre import mitre_attack_evidence
from .misp_detection import misp_detection_rule_evidence
from .misp_galaxy import misp_galaxy_evidence, single_misp_context_anchor
from .misp_metadata import (
    misp_metadata_evidence,
    misp_timeline_attributes,
    with_default_timeline,
)
from .misp_operational import (
    misp_campaign_evidence,
    misp_event_report_evidence,
    misp_infrastructure_evidence,
    misp_object_reference_evidence,
    misp_sighting_evidence,
    misp_victimology_evidence,
    misp_vulnerability_evidence,
)
from .misp_relationships import (
    misp_campaign_context_relationship_evidence,
    misp_infrastructure_context_relationship_evidence,
)
from .otx import otx_entity_evidence

def build_graph_evidence(metadata, source_key="", external_id="", title=""):
    metadata = metadata if isinstance(metadata, Mapping) else {}
    records = []
    records.extend(otx_entity_evidence(metadata.get("otx_entities"), source_key))
    records.extend(mitre_attack_evidence(metadata.get("mitre_attack"), source_key))
    records.extend(misp_metadata_evidence(metadata, source_key))
    misp_timeline = misp_timeline_attributes(metadata)
    misp_context_anchor = single_misp_context_anchor(metadata)
    records.extend(
        with_default_timeline(
            misp_galaxy_evidence(
                metadata.get("misp_galaxies"),
                source_key,
                misp_context_anchor,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_vulnerability_evidence(
                metadata.get("misp_vulnerabilities"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_campaign_evidence(metadata.get("misp_campaigns"), source_key),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_victimology_evidence(
                metadata.get("misp_victimology"),
                source_key,
                misp_context_anchor,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_event_report_evidence(
                metadata.get("misp_event_reports"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_sighting_evidence(metadata.get("misp_sightings"), source_key),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_object_reference_evidence(
                metadata.get("misp_object_references"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_infrastructure_evidence(
                metadata.get("misp_infrastructure"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        with_default_timeline(
            misp_detection_rule_evidence(
                metadata.get("misp_detection_rules"),
                source_key,
            ),
            misp_timeline,
        )
    )
    records.extend(
        misp_campaign_context_relationship_evidence(records, source_key)
    )
    records.extend(
        misp_infrastructure_context_relationship_evidence(records, source_key)
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
