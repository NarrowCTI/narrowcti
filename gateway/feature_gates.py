from dataclasses import dataclass

from narrowcti.adapters.entitlements.community import CommunityEntitlements
from narrowcti.application.capabilities import CapabilityRegistry
from narrowcti.infrastructure.capabilities import COMMUNITY_IMPLEMENTED_CAPABILITIES


AVAILABLE_CAPABILITIES = (
    "source.otx",
    "source.misp",
    "enrichment.otx_entities",
    "enrichment.mitre_attack",
    "quarantine.review",
    "quarantine.review_api",
    "reports.operational",
    "reports.operational_validation",
    "reports.support_diagnostics",
    "graph.export.audit",
    "graph.export.dry_run",
    "graph.lookup.opencti",
    "graph.export.controlled",
    "deployment.templates",
    "mssp.multi_environment",
)

_REGISTRY = CapabilityRegistry.default()
_ENTITLEMENTS = CommunityEntitlements()

@dataclass(frozen=True)
class FeatureGateState:
    distribution_model: str
    open_source: bool
    enforcement_enabled: bool
    available_capabilities: tuple[str, ...]
    enabled_capabilities: tuple[str, ...]
    disabled_capabilities: tuple[str, ...]
    requested_capabilities: tuple[str, ...]
    unknown_capabilities: tuple[str, ...]

    def to_dict(self):
        return {
            "distribution_model": self.distribution_model,
            "open_source": self.open_source,
            "enforcement_enabled": self.enforcement_enabled,
            "available_capabilities": list(self.available_capabilities),
            "enabled_capabilities": list(self.enabled_capabilities),
            "disabled_capabilities": list(self.disabled_capabilities),
            "requested_capabilities": list(self.requested_capabilities),
            "unknown_capabilities": list(self.unknown_capabilities),
        }


def build_feature_gate_state(requested_capabilities=None):
    requested = normalize_names(requested_capabilities or [])
    resolution = _REGISTRY.resolve(
        requested,
        implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
        entitled=_ENTITLEMENTS.granted_capabilities(),
    )
    unknown = tuple(
        capability for capability in requested if capability not in AVAILABLE_CAPABILITIES
    )
    valid_requested = tuple(
        capability for capability in requested if capability in AVAILABLE_CAPABILITIES
    )
    enabled = tuple(
        capability
        for capability in AVAILABLE_CAPABILITIES
        if _REGISTRY.resolve_name(capability) in resolution.enabled
    )
    disabled = tuple(capability for capability in AVAILABLE_CAPABILITIES if capability not in enabled)

    return FeatureGateState(
        distribution_model="open_source",
        open_source=True,
        enforcement_enabled=False,
        available_capabilities=AVAILABLE_CAPABILITIES,
        enabled_capabilities=enabled,
        disabled_capabilities=disabled,
        requested_capabilities=valid_requested,
        unknown_capabilities=unknown,
    )


def build_capability_inventory(requested_capabilities=None):
    """Return rich canonical state with the legacy preflight projection."""

    requested = normalize_names(requested_capabilities or [])
    resolution = _REGISTRY.resolve(
        requested,
        implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
        entitled=_ENTITLEMENTS.granted_capabilities(),
    )
    legacy = build_feature_gate_state(requested)
    inventory = resolution.to_dict()
    inventory.update(
        {
            "distribution_model": legacy.distribution_model,
            "open_source": legacy.open_source,
            "enforcement_enabled": legacy.enforcement_enabled,
            "available_capabilities": list(legacy.available_capabilities),
            "enabled_capabilities": list(legacy.enabled_capabilities),
            "disabled_capabilities": list(legacy.disabled_capabilities),
            "requested_capabilities": list(legacy.requested_capabilities),
            # The rich inventory reports canonical registry knowledge.  The
            # legacy FeatureGateState projection intentionally retains its
            # historical AVAILABLE_CAPABILITIES semantics above.
            "unknown_capabilities": list(resolution.unknown),
            "canonical_aliases": _REGISTRY.aliases,
        }
    )
    return inventory


def normalize_names(values):
    normalized = []
    for value in values:
        name = normalize_name(value)
        if name:
            normalized.append(name)
    return tuple(dict.fromkeys(normalized))


def normalize_name(value):
    return str(value or "").strip().lower().replace("-", "_")
