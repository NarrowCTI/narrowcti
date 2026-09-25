"""Pure capability namespace and resolution semantics.

This module deliberately has no runtime, adapter, filesystem, network, or
licensing dependencies.  Distribution-specific implementation and entitlement
sets are supplied by composition code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


COMMUNITY_CAPABILITY_NAMES = (
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

COMMUNITY_FUTURE_CAPABILITIES = (
    "ui.basic",
    "source.explorer",
    "ingestion.run_once",
)

COMMERCIAL_CAPABILITIES = (
    "ui.control_plane",
    "ingestion.scheduler",
    "ingestion.run_control",
    "audit.visual",
    "reporting.scheduled",
    "reporting.branding",
    "defensive_knowledge.d3fend",
    "defensive_knowledge.graph_promotion",
    "policy.advanced",
    "detection.requirements.advanced",
    "detection.telemetry_discovery",
    "detection.native_deployment",
    "validation.orchestration",
    "validation.openaev",
    "reporting.assurance",
    "governance.sso",
    "runtime.ha",
    "environment.multi",
    "mssp.multi_tenant",
    "mssp.tenant_isolation",
    "mssp.customer_branding",
    "mssp.delegated_admin",
    "mssp.cross_tenant_reporting",
)

DEFAULT_ALIASES = {
    "reports.operational": "reporting.operational",
    "reports.operational_validation": "reporting.operational_validation",
    "reports.support_diagnostics": "reporting.support_diagnostics",
    "mssp.multi_environment": "environment.multi",
}


def normalize_capability(value: object) -> str:
    """Normalize a capability name without granting or resolving it."""

    return str(value or "").strip().lower().replace("-", "_")


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


@dataclass(frozen=True)
class CapabilityResolution:
    """Immutable canonical capability state returned by the registry."""

    known: tuple[str, ...]
    implemented: tuple[str, ...]
    entitled: tuple[str, ...]
    requested: tuple[str, ...]
    enabled: tuple[str, ...]
    disabled: tuple[str, ...]
    unknown: tuple[str, ...]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "known": list(self.known),
            "implemented": list(self.implemented),
            "entitled": list(self.entitled),
            "requested": list(self.requested),
            "enabled": list(self.enabled),
            "disabled": list(self.disabled),
            "unknown": list(self.unknown),
        }


class CapabilityRegistry:
    """Deterministic registry for canonical names and compatibility aliases."""

    def __init__(
        self,
        capabilities: Iterable[str],
        aliases: Mapping[str, str] | None = None,
    ) -> None:
        normalized_capabilities: list[str] = []
        seen_capabilities: set[str] = set()
        for value in capabilities:
            name = normalize_capability(value)
            if not name:
                raise ValueError("capability registry contains an empty name")
            if name in seen_capabilities:
                raise ValueError(f"duplicate capability name: {name}")
            seen_capabilities.add(name)
            normalized_capabilities.append(name)

        canonical = tuple(sorted(normalized_capabilities))
        if not canonical:
            raise ValueError("capability registry cannot be empty")
        canonical_set = set(canonical)
        normalized_aliases: dict[str, str] = {}
        for key, value in (aliases or {}).items():
            alias = normalize_capability(key)
            target = normalize_capability(value)
            if not alias:
                raise ValueError("capability alias contains an empty name")
            if not target:
                raise ValueError("capability alias contains an empty target")
            if alias in normalized_aliases:
                raise ValueError(f"duplicate capability alias: {alias}")
            if alias in canonical_set:
                raise ValueError("capability alias collides with a canonical name")
            if target not in canonical_set:
                raise ValueError("capability alias points to an unknown canonical name")
            normalized_aliases[alias] = target
        self._capabilities = canonical
        self._capability_set = canonical_set
        self._aliases = dict(sorted(normalized_aliases.items()))

    @classmethod
    def default(cls) -> "CapabilityRegistry":
        return cls(
            (*COMMUNITY_CAPABILITY_NAMES, *COMMUNITY_FUTURE_CAPABILITIES, *COMMERCIAL_CAPABILITIES),
            DEFAULT_ALIASES,
        )

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self._capabilities

    @property
    def aliases(self) -> dict[str, str]:
        return dict(self._aliases)

    def resolve_name(self, value: object) -> str | None:
        name = normalize_capability(value)
        if name in self._capability_set:
            return name
        return self._aliases.get(name)

    def resolve(self, requested: Iterable[str] = (), *, implemented: Iterable[str] = (), entitled: Iterable[str] = ()) -> CapabilityResolution:
        requested_names: list[str] = []
        unknown: list[str] = []
        for value in requested or ():
            normalized = normalize_capability(value)
            if not normalized:
                continue
            canonical = self.resolve_name(normalized)
            if canonical is None:
                if normalized not in unknown:
                    unknown.append(normalized)
            elif canonical not in requested_names:
                requested_names.append(canonical)

        def resolve_set(values: Iterable[str]) -> set[str]:
            resolved = set()
            for value in values or ():
                canonical = self.resolve_name(value)
                if canonical is not None:
                    resolved.add(canonical)
            return resolved

        implemented_set = resolve_set(implemented)
        entitled_set = resolve_set(entitled)
        enabled_set = implemented_set & entitled_set
        known = self._capabilities
        return CapabilityResolution(
            known=known,
            implemented=tuple(name for name in known if name in implemented_set),
            entitled=tuple(name for name in known if name in entitled_set),
            requested=tuple(requested_names),
            enabled=tuple(name for name in known if name in enabled_set),
            disabled=tuple(name for name in known if name not in enabled_set),
            unknown=tuple(unknown),
        )


__all__ = [
    "CapabilityRegistry",
    "CapabilityResolution",
    "COMMERCIAL_CAPABILITIES",
    "COMMUNITY_FUTURE_CAPABILITIES",
    "COMMUNITY_CAPABILITY_NAMES",
    "DEFAULT_ALIASES",
    "normalize_capability",
]
