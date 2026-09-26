"""Detection intent contracts independent of providers and rule formats."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ._normalization import confidence_value, normalize_refs, optional_text, positive_version, required_text
from .lifecycle import normalize_lifecycle


@dataclass(frozen=True)
class DetectionScope:
    tenant_id: str | None = None
    environment_id: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "tenant_id", optional_text(self.tenant_id, "tenant_id"))
        object.__setattr__(
            self,
            "environment_id",
            optional_text(self.environment_id, "environment_id"),
        )

    def to_dict(self):
        return {"tenant_id": self.tenant_id, "environment_id": self.environment_id}

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("scope must be a mapping")
        return cls(value.get("tenant_id"), value.get("environment_id"))


@dataclass(frozen=True)
class ThreatContext:
    actor: str = ""
    campaign: str = ""
    malware: str = ""

    def __post_init__(self):
        object.__setattr__(self, "actor", optional_text(self.actor, "actor") or "")
        object.__setattr__(self, "campaign", optional_text(self.campaign, "campaign") or "")
        object.__setattr__(self, "malware", optional_text(self.malware, "malware") or "")

    def to_dict(self):
        return {
            "actor": self.actor,
            "campaign": self.campaign,
            "malware": self.malware,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("threat_context must be a mapping")
        return cls(value.get("actor"), value.get("campaign"), value.get("malware"))


@dataclass(frozen=True)
class DetectionBehavior:
    attack_id: str
    procedure: str = ""

    def __post_init__(self):
        normalized_attack_id = required_text(self.attack_id, "attack_id").upper()
        object.__setattr__(self, "attack_id", normalized_attack_id)
        object.__setattr__(self, "procedure", optional_text(self.procedure, "procedure") or "")

    def to_dict(self):
        return {"attack_id": self.attack_id, "procedure": self.procedure}

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("behavior must be a mapping")
        return cls(value.get("attack_id"), value.get("procedure", ""))


@dataclass(frozen=True)
class DetectionRequirement:
    id: str
    scope: DetectionScope
    behavior: DetectionBehavior
    source_refs: tuple[str, ...] = ()
    threat_context: ThreatContext = ThreatContext()
    priority: str = ""
    rationale: str = ""
    confidence: int | None = None
    provenance: tuple[str, ...] = ()
    telemetry_requirements: tuple[str, ...] = ()
    lifecycle: str = "proposed"
    version: int = 1

    def __post_init__(self):
        object.__setattr__(self, "id", required_text(self.id, "id"))
        if not isinstance(self.scope, DetectionScope):
            raise ValueError("scope must be a DetectionScope")
        if not isinstance(self.threat_context, ThreatContext):
            raise ValueError("threat_context must be a ThreatContext")
        if not isinstance(self.behavior, DetectionBehavior):
            raise ValueError("behavior must be a DetectionBehavior")
        object.__setattr__(self, "source_refs", normalize_refs(self.source_refs, "source_refs"))
        object.__setattr__(self, "provenance", normalize_refs(self.provenance, "provenance"))
        object.__setattr__(
            self,
            "telemetry_requirements",
            normalize_refs(self.telemetry_requirements, "telemetry_requirements"),
        )
        object.__setattr__(self, "priority", optional_text(self.priority, "priority") or "")
        object.__setattr__(self, "rationale", optional_text(self.rationale, "rationale") or "")
        object.__setattr__(self, "confidence", confidence_value(self.confidence))
        object.__setattr__(self, "lifecycle", normalize_lifecycle(self.lifecycle))
        object.__setattr__(self, "version", positive_version(self.version))

    def to_dict(self):
        return {
            "id": self.id,
            "scope": self.scope.to_dict(),
            "source_refs": list(self.source_refs),
            "threat_context": self.threat_context.to_dict(),
            "behavior": self.behavior.to_dict(),
            "relevance": {"priority": self.priority, "rationale": self.rationale},
            "evidence": {
                "confidence": self.confidence,
                "references": list(self.source_refs),
                "provenance": list(self.provenance),
            },
            "telemetry_requirements": list(self.telemetry_requirements),
            "lifecycle": self.lifecycle,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("detection requirement must be a mapping")
        relevance = value.get("relevance", {})
        if not isinstance(relevance, Mapping):
            raise ValueError("relevance must be a mapping")
        evidence = value.get("evidence", {})
        if not isinstance(evidence, Mapping):
            raise ValueError("evidence must be a mapping")
        source_refs = value.get("source_refs")
        evidence_refs = evidence.get("references")
        if source_refs is not None and evidence_refs is not None:
            if normalize_refs(source_refs, "source_refs") != normalize_refs(
                evidence_refs, "evidence.references"
            ):
                raise ValueError("source_refs and evidence.references disagree")
        return cls(
            id=value.get("id"),
            scope=DetectionScope.from_dict(value.get("scope") or {}),
            source_refs=source_refs if source_refs is not None else evidence_refs or (),
            threat_context=ThreatContext.from_dict(value.get("threat_context") or {}),
            behavior=DetectionBehavior.from_dict(value.get("behavior") or {}),
            priority=relevance.get("priority", ""),
            rationale=relevance.get("rationale", ""),
            confidence=evidence.get("confidence"),
            provenance=evidence.get("provenance") or (),
            telemetry_requirements=value.get("telemetry_requirements") or (),
            lifecycle=value.get("lifecycle", "proposed"),
            version=value.get("version", 1),
        )


__all__ = [
    "DetectionBehavior",
    "DetectionRequirement",
    "DetectionScope",
    "ThreatContext",
]
