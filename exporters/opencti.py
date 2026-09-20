"""Historical OpenCTI exporter compatibility surface."""

from narrowcti.adapters.opencti import exporter as _canonical


_COMPATIBILITY_NAMES = (
    "OpenCTIImportRejectedError",
    "capture_pycti_worker_errors",
    "send_bundle",
    "import_rejection_message",
    "export_native_security_platforms",
    "export_native_detection_rule_indicators",
    "export_native_threat_actor_individuals",
    "link_native_objects_to_reports",
    "link_native_security_platforms_to_reports",
    "report_nodes_for_bundle",
    "report_refs_from_bundle_json",
    "find_report",
    "native_security_platform_candidates",
    "native_threat_actor_individual_candidates",
    "native_detection_rule_indicator_candidates",
    "find_identity",
    "find_indicator",
    "find_label",
    "add_label",
    "resolve_label_ids",
    "find_security_platform",
    "find_threat_actor_individual",
    "candidate_existing_id",
    "hydrate_existing_graph_descriptions",
    "has_narrowcti_author",
    "graph_candidate_name",
    "graph_candidate_confidence",
    "candidate_attributes",
    "clean_string",
    "clean_multiline_string",
    "clean_edge_string",
    "clean_list_values",
    "DESCRIPTION_READ_QUERY",
    "DESCRIPTION_PATCH_MUTATION",
    "SECURITY_PLATFORM_LOOKUP_QUERY",
    "SECURITY_PLATFORM_ADD_MUTATION",
    "THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY",
    "THREAT_ACTOR_INDIVIDUAL_ADD_MUTATION",
    "IDENTITY_LOOKUP_QUERY",
    "INDICATOR_LOOKUP_QUERY",
    "INDICATOR_ADD_MUTATION",
    "LABEL_LOOKUP_QUERY",
    "LABEL_ADD_MUTATION",
    "REPORT_LOOKUP_QUERY",
    "REPORT_OBJECT_REF_ADD_MUTATION",
)

for _name in _COMPATIBILITY_NAMES:
    globals()[_name] = getattr(_canonical, _name)

_PyCTIWorkerLoggerProxy = _canonical._PyCTIWorkerLoggerProxy

__all__ = _COMPATIBILITY_NAMES + ("_PyCTIWorkerLoggerProxy",)
