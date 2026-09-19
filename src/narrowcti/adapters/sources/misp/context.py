from __future__ import annotations

from .detection_rules import extract_misp_detection_rules
from .entities import (
    extract_misp_campaigns,
    extract_misp_event_reports,
    extract_misp_galaxies,
    extract_misp_object_references,
    extract_misp_sightings,
    extract_misp_victimology,
    extract_misp_vulnerabilities,
)
from .infrastructure import extract_misp_infrastructure


def extract_misp_context(source, *, tags=None, ip_asn_enricher=None):
    """Compose source-specific MISP context without runtime orchestration."""
    metadata = {}
    misp_galaxies = extract_misp_galaxies(source)
    if misp_galaxies:
        metadata["misp_galaxies"] = misp_galaxies
    misp_vulnerabilities = extract_misp_vulnerabilities(source, tags or [])
    if misp_vulnerabilities:
        metadata["misp_vulnerabilities"] = misp_vulnerabilities
    misp_campaigns = extract_misp_campaigns(source)
    if misp_campaigns:
        metadata["misp_campaigns"] = misp_campaigns
    misp_victimology = extract_misp_victimology(source)
    if misp_victimology:
        metadata["misp_victimology"] = misp_victimology
    misp_event_reports = extract_misp_event_reports(source)
    if misp_event_reports:
        metadata["misp_event_reports"] = misp_event_reports
    misp_sightings = extract_misp_sightings(source)
    if misp_sightings:
        metadata["misp_sightings"] = misp_sightings
    misp_object_references = extract_misp_object_references(source)
    if misp_object_references:
        metadata["misp_object_references"] = misp_object_references
    misp_infrastructure = extract_misp_infrastructure(
        source,
        ip_asn_enricher=ip_asn_enricher,
    )
    if misp_infrastructure:
        metadata["misp_infrastructure"] = misp_infrastructure
    misp_detection_rules = extract_misp_detection_rules(source)
    if misp_detection_rules:
        metadata["misp_detection_rules"] = misp_detection_rules
    return metadata
