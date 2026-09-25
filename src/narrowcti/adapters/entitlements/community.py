"""Offline Community entitlement provider."""

from narrowcti.ports.entitlements import EntitlementProvider


COMMUNITY_ENTITLED_CAPABILITIES = (
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


class CommunityEntitlements:
    """Static, deterministic Community grants with no external I/O."""

    def granted_capabilities(self) -> tuple[str, ...]:
        return COMMUNITY_ENTITLED_CAPABILITIES


assert isinstance(CommunityEntitlements(), EntitlementProvider)

__all__ = ["COMMUNITY_ENTITLED_CAPABILITIES", "CommunityEntitlements"]
