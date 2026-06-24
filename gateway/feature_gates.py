from dataclasses import dataclass


AVAILABLE_CAPABILITIES = (
    "source.otx",
    "source.misp",
    "enrichment.otx_entities",
    "enrichment.mitre_attack",
    "quarantine.review",
    "reports.operational",
    "reports.support_diagnostics",
    "graph.export.audit",
    "graph.export.dry_run",
    "graph.lookup.opencti",
    "graph.export.controlled",
    "deployment.templates",
    "mssp.multi_environment",
)

EDITION_CAPABILITIES = {
    "evaluation": (
        "source.otx",
        "source.misp",
        "enrichment.otx_entities",
        "enrichment.mitre_attack",
        "quarantine.review",
        "reports.operational",
        "reports.support_diagnostics",
        "graph.export.audit",
        "graph.export.dry_run",
    ),
    "professional": (
        "source.otx",
        "source.misp",
        "enrichment.otx_entities",
        "enrichment.mitre_attack",
        "quarantine.review",
        "reports.operational",
        "reports.support_diagnostics",
        "graph.export.audit",
        "graph.export.dry_run",
        "graph.lookup.opencti",
        "deployment.templates",
    ),
    "enterprise": (
        "source.otx",
        "source.misp",
        "enrichment.otx_entities",
        "enrichment.mitre_attack",
        "quarantine.review",
        "reports.operational",
        "reports.support_diagnostics",
        "graph.export.audit",
        "graph.export.dry_run",
        "graph.lookup.opencti",
        "graph.export.controlled",
        "deployment.templates",
    ),
    "mssp": AVAILABLE_CAPABILITIES,
}


@dataclass(frozen=True)
class FeatureGateState:
    edition: str
    known_edition: bool
    license_configured: bool
    enforcement_enabled: bool
    available_capabilities: tuple[str, ...]
    enabled_capabilities: tuple[str, ...]
    requested_capabilities: tuple[str, ...]
    unknown_capabilities: tuple[str, ...]

    def to_dict(self):
        return {
            "edition": self.edition,
            "known_edition": self.known_edition,
            "license_configured": self.license_configured,
            "enforcement_enabled": self.enforcement_enabled,
            "available_capabilities": list(self.available_capabilities),
            "enabled_capabilities": list(self.enabled_capabilities),
            "requested_capabilities": list(self.requested_capabilities),
            "unknown_capabilities": list(self.unknown_capabilities),
        }


def build_feature_gate_state(
    edition,
    license_file="",
    enforcement_enabled=False,
    requested_capabilities=None,
):
    normalized_edition = normalize_name(edition) or "evaluation"
    known_edition = normalized_edition in EDITION_CAPABILITIES
    requested = normalize_names(requested_capabilities or [])
    unknown = tuple(
        capability for capability in requested if capability not in AVAILABLE_CAPABILITIES
    )
    valid_requested = tuple(
        capability for capability in requested if capability in AVAILABLE_CAPABILITIES
    )
    default_capabilities = EDITION_CAPABILITIES.get(normalized_edition, ())
    enabled = valid_requested or default_capabilities

    return FeatureGateState(
        edition=normalized_edition,
        known_edition=known_edition,
        license_configured=bool(str(license_file or "").strip()),
        enforcement_enabled=bool(enforcement_enabled),
        available_capabilities=AVAILABLE_CAPABILITIES,
        enabled_capabilities=tuple(enabled),
        requested_capabilities=requested,
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
