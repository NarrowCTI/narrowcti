import ast
import importlib
from pathlib import Path


LEGACY_GRAPH_EVIDENCE_SYMBOLS = {
    "re",
    "Counter",
    "Mapping",
    "extract_tlp_values",
    "normalize_tlp",
    "GRAPH_EVIDENCE_VERSION",
    "ENTITY_TARGETS",
    "TARGET_SECTOR_ALIASES",
    "TARGET_COUNTRY_ALIASES",
    "TARGET_REGION_ALIASES",
    "INTRUSION_SET_ALIASES",
    "MALWARE_ALIASES",
    "ATTACK_ID_PATTERN",
    "CVE_ID_PATTERN",
    "MISP_GALAXY_TAG_PATTERN",
    "MISP_INFRA_CONTEXT_MAX_INFRASTRUCTURES",
    "MISP_INFRA_CONTEXT_MAX_PAIRINGS",
    "MISP_INFRA_CONTEXT_MAX_RECORDS",
    "MISP_INFRA_CAPABILITY_ENTITY_TYPES",
    "MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES",
    "MISP_CAMPAIGN_CONTEXT_MAX_CAMPAIGNS",
    "MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS",
    "MISP_CAMPAIGN_CONTEXT_MAX_RECORDS",
    "MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES",
    "MISP_CAMPAIGN_CAPABILITY_ENTITY_TYPES",
    "build_graph_evidence",
    "with_default_timeline",
    "misp_timeline_attributes",
    "otx_entity_evidence",
    "otx_timeline_attributes",
    "mitre_attack_evidence",
    "misp_metadata_evidence",
    "misp_galaxy_tag_clusters",
    "misp_galaxy_evidence",
    "MISP_GALAXY_CONTEXT_ANCHOR_ENTITY_TYPES",
    "misp_galaxy_uses_context_anchor",
    "misp_galaxy_meta_evidence",
    "misp_galaxy_meta_relationship_anchor",
    "MISP_GALAXY_META_ENTITY_FIELDS",
    "TARGET_ORGANIZATION_VALUE_DENYLIST",
    "TARGET_INDIVIDUAL_VALUE_DENYLIST",
    "is_target_organization_value",
    "is_dotted_identifier_value",
    "is_target_individual_value",
    "is_safe_misp_meta_graph_value",
    "meta_source_field",
    "misp_galaxy_meta_attributes",
    "misp_meta_context_types",
    "classify_misp_galaxy",
    "misp_galaxy_value",
    "misp_galaxy_is_threat_actor_individual",
    "first_attack_id_from_cluster",
    "first_cve_id_from_cluster",
    "misp_galaxy_attributes",
    "misp_galaxy_relationship_type",
    "first_mitigated_attack_id_from_cluster",
    "misp_vulnerability_evidence",
    "misp_campaign_evidence",
    "misp_victimology_evidence",
    "single_misp_context_anchor",
    "misp_campaign_anchors",
    "misp_galaxy_anchors",
    "single_unique_anchor",
    "misp_event_report_evidence",
    "misp_sighting_evidence",
    "misp_sighting_confidence",
    "misp_object_reference_evidence",
    "misp_infrastructure_evidence",
    "misp_infrastructure_context_relationship_evidence",
    "misp_campaign_context_relationship_evidence",
    "infrastructure_anchor_relationship_records",
    "context_anchor_relationship_records",
    "infrastructure_attack_pattern_relationship_records",
    "infrastructure_victimology_relationship_records",
    "unique_context_records",
    "semantic_relationship_keys",
    "semantic_relationship_key",
    "misp_detection_rule_evidence",
    "evidence_record",
    "evidence_confidence",
    "TARGET_LOCATION_ENTITY_TYPES",
    "target_sector_confidence",
    "target_location_confidence",
    "intrusion_set_confidence",
    "malware_confidence",
    "normalize_evidence_value",
    "normalize_alias_value",
    "compact_mapping",
    "clean_string",
    "clean_values",
    "flatten_values",
    "mitre_external_references",
    "mitre_context_attributes",
    "mitre_data_component_from_data_source",
    "mitre_kill_chain_phases",
    "clamp_confidence",
    "first_confidence_value",
}


def test_legacy_graph_evidence_surface_is_preserved():
    legacy = importlib.import_module("core.graph_evidence")
    canonical = importlib.import_module("narrowcti.domain.graph.evidence")

    missing = sorted(
        name for name in LEGACY_GRAPH_EVIDENCE_SYMBOLS if not hasattr(legacy, name)
    )
    assert not missing
    assert legacy.build_graph_evidence is canonical.build_graph_evidence
    assert legacy.clamp_confidence is canonical.clamp_confidence
    assert legacy.GRAPH_EVIDENCE_VERSION == canonical.GRAPH_EVIDENCE_VERSION
    assert canonical.GRAPH_EVIDENCE_VERSION == "v1.0.0"


def test_legacy_and_canonical_imports_share_function_symbols_in_both_orders():
    legacy = importlib.import_module("core.graph_evidence")
    canonical = importlib.import_module("narrowcti.domain.graph.evidence")
    assert legacy.build_graph_evidence is canonical.build_graph_evidence
    assert legacy.clamp_confidence is canonical.clamp_confidence


def test_domain_graph_modules_do_not_import_runtime_boundaries():
    root = Path(__file__).parents[1] / "src" / "narrowcti" / "domain" / "graph"
    forbidden = (
        "core",
        "connectors",
        "gateway",
        "exporters",
        "application",
        "adapters",
        "infrastructure",
        "api",
    )
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            else:
                continue
            for module in imported:
                assert not any(
                    module == prefix or module.startswith(prefix + ".")
                    for prefix in forbidden
                ), (path, module)


def test_misp_tag_galaxy_records_remain_before_standalone_galaxy_records():
    evidence = importlib.import_module(
        "narrowcti.domain.graph.evidence"
    ).build_graph_evidence(
        {
            "tags": ['misp-galaxy:mitre-intrusion-set="Tagged Actor"'],
            "misp_galaxies": [
                {
                    "type": "intrusion-set",
                    "value": "Standalone Actor",
                    "galaxy_type": "mitre-intrusion-set",
                    "source_field": "Galaxy[0]",
                }
            ],
        },
        source_key="misp:misp",
    )
    galaxy_records = [
        record
        for record in evidence["records"]
        if record.get("source_name") == "misp-galaxy"
        and record.get("entity_type") == "intrusion_set"
    ]
    assert [record["value"] for record in galaxy_records] == [
        "Tagged Actor",
        "Standalone Actor",
    ]
