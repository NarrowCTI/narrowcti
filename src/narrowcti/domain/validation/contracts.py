"""Provider-neutral validation intent contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from narrowcti.domain.detection.requirements import DetectionBehavior

from narrowcti.domain.detection._normalization import normalize_refs, positive_version, required_text


VALIDATION_CONTRACT_FIELDS = (
    "id",
    "requirement_id",
    "artifact_id",
    "behavior",
    "provider_preference",
    "expected_telemetry",
    "expected_detection",
    "evidence_required",
    "provenance",
    "version",
)


@dataclass(frozen=True)
class ValidationContract:
    id: str
    requirement_id: str
    behavior: DetectionBehavior
    artifact_id: str | None = None
    provider_preference: tuple[str, ...] = ()
    expected_telemetry: tuple[str, ...] = ()
    expected_detection: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    version: int = 1

    def __post_init__(self):
        object.__setattr__(self, "id", required_text(self.id, "id"))
        object.__setattr__(self, "requirement_id", required_text(self.requirement_id, "requirement_id"))
        if not isinstance(self.behavior, DetectionBehavior):
            raise ValueError("behavior must be a DetectionBehavior")
        if self.artifact_id is not None:
            object.__setattr__(self, "artifact_id", required_text(self.artifact_id, "artifact_id"))
        object.__setattr__(self, "provider_preference", normalize_refs(self.provider_preference, "provider_preference"))
        object.__setattr__(self, "expected_telemetry", normalize_refs(self.expected_telemetry, "expected_telemetry"))
        object.__setattr__(self, "expected_detection", normalize_refs(self.expected_detection, "expected_detection"))
        evidence_required = normalize_refs(self.evidence_required, "evidence_required")
        if not evidence_required:
            raise ValueError("evidence_required must not be empty")
        object.__setattr__(self, "evidence_required", evidence_required)
        object.__setattr__(self, "provenance", normalize_refs(self.provenance, "provenance"))
        object.__setattr__(self, "version", positive_version(self.version))

    def to_dict(self):
        return {
            "id": self.id,
            "requirement_id": self.requirement_id,
            "artifact_id": self.artifact_id,
            "behavior": self.behavior.to_dict(),
            "provider_preference": list(self.provider_preference),
            "expected": {
                "telemetry": list(self.expected_telemetry),
                "detection": list(self.expected_detection),
            },
            "evidence_required": list(self.evidence_required),
            "provenance": list(self.provenance),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("validation contract must be a mapping")
        expected = value.get("expected") or {}
        return cls(
            id=value.get("id"),
            requirement_id=value.get("requirement_id"),
            artifact_id=value.get("artifact_id"),
            behavior=DetectionBehavior.from_dict(value.get("behavior") or {}),
            provider_preference=value.get("provider_preference") or (),
            expected_telemetry=expected.get("telemetry") or (),
            expected_detection=expected.get("detection") or (),
            evidence_required=value.get("evidence_required") or (),
            provenance=value.get("provenance") or (),
            version=value.get("version", 1),
        )


__all__ = ["VALIDATION_CONTRACT_FIELDS", "ValidationContract"]
