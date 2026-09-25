"""Explicit Community implementation manifest used by runtime composition."""

COMMUNITY_IMPLEMENTED_CAPABILITIES = (
    "source.otx",
    "source.misp",
    "enrichment.otx_entities",
    "enrichment.mitre_attack",
    "curation.scoring",
    "curation.contextual_scoring",
    "quarantine.review",
    "quarantine.review_api",
    "reporting.operational",
    "reporting.operational_validation",
    "reporting.support_diagnostics",
    "graph.export.audit",
    "graph.export.dry_run",
    "graph.lookup.opencti",
    "graph.export.controlled",
    "deployment.templates",
)

__all__ = ["COMMUNITY_IMPLEMENTED_CAPABILITIES"]
