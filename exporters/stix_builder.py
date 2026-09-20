"""Historical STIX builder compatibility surface.

The canonical graph/STIX implementation lives in
``narrowcti.adapters.opencti.graph_serializer``.  This module deliberately
lists the supported compatibility names instead of mirroring incidental
third-party imports.
"""

# These imports are deliberate compatibility-only module attributes.
# ruff: noqa: F401

from stix2 import (
    Artifact,
    AttackPattern,
    AutonomousSystem,
    Bundle,
    Campaign,
    CourseOfAction,
    CustomObject,
    DomainName,
    EmailAddress,
    ExtensionDefinition,
    File,
    IPv4Address,
    IPv6Address,
    Identity,
    Infrastructure,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    Note,
    Relationship,
    Report,
    Sighting,
    ThreatActor,
    Tool,
    URL,
    Vulnerability,
)
from stix2.properties import StringProperty
from stix2.registry import class_for_type

from narrowcti.adapters.opencti import graph_serializer as _canonical_graph
from narrowcti.adapters.opencti.stix_profile import (
    OPENCTI_CUSTOM_SDO_TYPES,
    OPENCTI_EXTENSION_DEFINITION_ID,
    opencti_extension_objects,
)
from narrowcti.adapters.stix.identifiers import (
    GRAPH_OBJECT_ID_NAMESPACE,
    deterministic_graph_object_id,
    deterministic_identity_id,
    deterministic_report_id,
)
from narrowcti.adapters.stix.patterns import escape_pattern_value, indicator_pattern
from narrowcti.adapters.stix.serializer import (
    build_identity,
    build_indicators,
    build_report_bundle,
    build_stix_report,
)


_GRAPH_COMPATIBILITY_NAMES = (
    "registered_custom_object",
    "MitreDataSource",
    "MitreDataComponent",
    "SEMANTIC_RELATIONSHIP_TYPES",
    "DETECTION_RULE_INDICATOR_PATTERN_TYPES",
    "DETECTION_RULE_NOTE_PATTERN_TYPES",
    "CUSTOM_GRAPH_OBJECTS",
    "OPERATIONAL_CONTEXT_ENTITY_TYPES",
    "TARGET_CONTEXT_ENTITY_TYPES",
    "build_curated_report_bundle",
    "build_graph_report_bundle",
    "indicator_object_ids",
    "build_graph_content",
    "build_graph_relationships",
    "graph_bundle_summary",
    "graph_accepted_candidates",
    "graph_description_hydration_requests",
    "existing_opencti_ref",
    "graph_candidate_hydrates_existing_ref",
    "candidate_existing_ref_prefixes",
    "graph_candidate_to_stix_object",
    "opencti_custom_sdo_candidate_to_stix",
    "graph_candidate_is_relationship_only",
    "graph_identity_class",
    "autonomous_system_candidate_to_stix",
    "autonomous_system_number",
    "autonomous_system_name",
    "parse_autonomous_system_number",
    "deterministic_autonomous_system_id",
    "location_candidate_to_stix",
    "opencti_location_type_for_candidate",
    "graph_candidate_description",
    "source_backed_context_description",
    "deterministic_location_id",
    "parse_position",
    "parse_float",
    "observable_candidate_to_stix",
    "attack_pattern_references",
    "attack_pattern_kill_chain_phases",
    "vulnerability_references",
    "detection_rule_stix_object_type",
    "detection_rule_indicator_name",
    "detection_rule_pattern_type",
    "detection_rule_indicator_compatible",
    "detection_rule_candidate_to_note",
    "detection_rule_note_content",
    "detection_rule_indicator_properties",
    "detection_rule_labels",
    "detection_rule_external_references",
    "graph_custom_properties",
    "graph_timeline_custom_properties",
    "graph_relationship_custom_properties",
    "graph_relationship_temporal_kwargs",
    "graph_special_relationship",
    "object_reference_candidate_to_relationship",
    "sighting_candidate_to_stix",
    "graph_special_relationship_type",
    "graph_special_relationship_key",
    "sighting_target_is_sdo",
    "positive_sighting",
    "deterministic_sighting_id",
    "parse_sighting_time",
    "parse_timestamp",
    "source_publication_time",
    "stix_timestamp",
    "graph_relationship_endpoint",
    "graph_relationship_source_ref",
    "graph_relationship_target_ref",
    "graph_relationship_is_candidate_to_anchor",
    "graph_relationship_source_key",
    "register_graph_object_aliases",
    "candidate_alias_keys",
    "alias_key",
    "candidate_attributes",
    "parent_cluster_stix_object_type",
    "first_clean_value",
    "clean_list_values",
    "stix_object_field",
    "graph_object_key",
    "candidate_summary",
    "normalize_hash_algorithm",
    "clamp_stix_confidence",
    "clean_string",
    "clean_multiline_string",
)

for _name in _GRAPH_COMPATIBILITY_NAMES:
    globals()[_name] = getattr(_canonical_graph, _name)


__all__ = tuple(
    dict.fromkeys(
        [
            *_GRAPH_COMPATIBILITY_NAMES,
            "build_identity",
            "build_indicators",
            "build_report_bundle",
            "build_stix_report",
            "escape_pattern_value",
            "indicator_pattern",
            "deterministic_graph_object_id",
            "deterministic_identity_id",
            "deterministic_report_id",
            "opencti_extension_objects",
        ]
    )
)
