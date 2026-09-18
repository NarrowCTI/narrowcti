"""Deterministic submodule compatibility aliases for the staged src migration."""

from __future__ import annotations

from importlib import import_module
import sys
from types import ModuleType

LEGACY_MODULE_ALIASES: dict[str, str] = {
    "narrowcti.connectors.misp.client": "connectors.misp.client",
    "narrowcti.connectors.misp.connector": "connectors.misp.connector",
    "narrowcti.connectors.misp.feed_adapter": "connectors.misp.feed_adapter",
    "narrowcti.connectors.misp.models": "connectors.misp.models",
    "narrowcti.connectors.misp.processor": "connectors.misp.processor",
    "narrowcti.connectors.misp.runtime": "connectors.misp.runtime",
    "narrowcti.connectors.misp.settings": "connectors.misp.settings",
    "narrowcti.connectors.otx.connector": "connectors.otx.connector",
    "narrowcti.connectors.otx.entity_extraction": "connectors.otx.entity_extraction",
    "narrowcti.connectors.otx.feed_adapter": "connectors.otx.feed_adapter",
    "narrowcti.connectors.otx.models": "connectors.otx.models",
    "narrowcti.connectors.otx.otx_client": "connectors.otx.otx_client",
    "narrowcti.connectors.otx.processor": "connectors.otx.processor",
    "narrowcti.connectors.otx.runtime": "connectors.otx.runtime",
    "narrowcti.connectors.otx.settings": "connectors.otx.settings",
    "narrowcti.core.atomic_io": "core.atomic_io",
    "narrowcti.core.contextual_scoring": "core.contextual_scoring",
    "narrowcti.core.decision_audit": "core.decision_audit",
    "narrowcti.core.deduplication": "core.deduplication",
    "narrowcti.core.feed_contract": "core.feed_contract",
    "narrowcti.core.graph_candidates": "core.graph_candidates",
    "narrowcti.core.graph_deduplication": "core.graph_deduplication",
    "narrowcti.core.graph_evidence": "core.graph_evidence",
    "narrowcti.core.graph_export_plan": "core.graph_export_plan",
    "narrowcti.core.indicator_policy": "core.indicator_policy",
    "narrowcti.core.ip_asn_enrichment": "core.ip_asn_enrichment",
    "narrowcti.core.mitre_attack": "core.mitre_attack",
    "narrowcti.core.opencti_deduplication": "core.opencti_deduplication",
    "narrowcti.core.opencti_graph_lookup": "core.opencti_graph_lookup",
    "narrowcti.core.policy": "core.policy",
    "narrowcti.core.quarantine": "core.quarantine",
    "narrowcti.core.retry": "core.retry",
    "narrowcti.core.runtime_config": "core.runtime_config",
    "narrowcti.core.scoring": "core.scoring",
    "narrowcti.core.source_identity": "core.source_identity",
    "narrowcti.core.state_repository": "core.state_repository",
    "narrowcti.core.tlp": "core.tlp",
    "narrowcti.exporters.opencti": "exporters.opencti",
    "narrowcti.exporters.stix_builder": "exporters.stix_builder",
    "narrowcti.gateway.connector": "gateway.connector",
    "narrowcti.gateway.correlation": "gateway.correlation",
    "narrowcti.gateway.curation_report": "gateway.curation_report",
    "narrowcti.gateway.decisions": "gateway.decisions",
    "narrowcti.gateway.diagnostics": "gateway.diagnostics",
    "narrowcti.gateway.feature_gates": "gateway.feature_gates",
    "narrowcti.gateway.mitre": "gateway.mitre",
    "narrowcti.gateway.opencti_client_validation": "gateway.opencti_client_validation",
    "narrowcti.gateway.opencti_client": "gateway.opencti_client",
    "narrowcti.gateway.opencti_relationship_audit": "gateway.opencti_relationship_audit",
    "narrowcti.gateway.operational_validation": "gateway.operational_validation",
    "narrowcti.gateway.preflight": "gateway.preflight",
    "narrowcti.gateway.quarantine_export": "gateway.quarantine_export",
    "narrowcti.gateway.quarantine": "gateway.quarantine",
    "narrowcti.gateway.report": "gateway.report",
    "narrowcti.gateway.review_api": "gateway.review_api",
    "narrowcti.gateway.review_auth": "gateway.review_auth",
    "narrowcti.gateway.review": "gateway.review",
    "narrowcti.gateway.runtime": "gateway.runtime",
    "narrowcti.gateway.settings": "gateway.settings",
    "narrowcti.gateway.sources": "gateway.sources",
}


def alias_submodule(canonical_name: str) -> ModuleType:
    """Load one legacy module and bind the canonical name to the same object.

    The alias table is static and exhaustive for current runtime modules. No
    path mutation, filesystem discovery or import hook is involved.
    """
    try:
        legacy_name = LEGACY_MODULE_ALIASES[canonical_name]
    except KeyError as exc:
        raise ImportError(f"unsupported NarrowCTI compatibility module: {canonical_name}") from exc
    module = import_module(legacy_name)
    sys.modules[canonical_name] = module
    return module


__all__ = ["LEGACY_MODULE_ALIASES", "alias_submodule"]
