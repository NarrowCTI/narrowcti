from dataclasses import dataclass


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
    unknown = tuple(
        capability for capability in requested if capability not in AVAILABLE_CAPABILITIES
    )
    valid_requested = tuple(
        capability for capability in requested if capability in AVAILABLE_CAPABILITIES
    )

    return FeatureGateState(
        distribution_model="open_source",
        open_source=True,
        enforcement_enabled=False,
        available_capabilities=AVAILABLE_CAPABILITIES,
        enabled_capabilities=AVAILABLE_CAPABILITIES,
        disabled_capabilities=(),
        requested_capabilities=valid_requested,
        unknown_capabilities=unknown,
    )


def normalize_names(values):
    normalized = []
    for value in values:
        name = normalize_name(value)
        if name:
            normalized.append(name)
    return tuple(dict.fromkeys(normalized))


def normalize_name(value):
    return str(value or "").strip().lower().replace("-", "_")
