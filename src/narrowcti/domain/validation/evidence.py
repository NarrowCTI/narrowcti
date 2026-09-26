"""Immutable normalized validation evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

from narrowcti.domain.detection._normalization import (
    normalize_refs,
    non_negative_int,
    optional_text,
    positive_version,
    required_text,
)


VALIDATION_EVIDENCE_STATUSES = ("passed", "failed", "incomplete", "unknown")
ValidationEvidenceStatus = Literal["passed", "failed", "incomplete", "unknown"]


@dataclass(frozen=True)
class ValidationEvidence:
    id: str
    validation_contract_id: str
    detection_artifact_id: str
    artifact_version: str
    telemetry_contract_id: str
    telemetry_contract_version: int
    status: ValidationEvidenceStatus
    provider: str
    execution_ref: str | None = None
    telemetry_observed: bool | None = None
    telemetry_refs: tuple[str, ...] = ()
    detection_observed: bool | None = None
    alert_refs: tuple[str, ...] = ()
    latency_ms: int | None = None
    started_at: str | None = None
    completed_at: str | None = None
    provenance: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "id", required_text(self.id, "id"))
        object.__setattr__(self, "validation_contract_id", required_text(self.validation_contract_id, "validation_contract_id"))
        object.__setattr__(self, "detection_artifact_id", required_text(self.detection_artifact_id, "detection_artifact_id"))
        object.__setattr__(self, "artifact_version", required_text(self.artifact_version, "artifact_version"))
        object.__setattr__(self, "telemetry_contract_id", required_text(self.telemetry_contract_id, "telemetry_contract_id"))
        object.__setattr__(
            self,
            "telemetry_contract_version",
            positive_version(self.telemetry_contract_version, "telemetry_contract_version"),
        )
        status = required_text(self.status, "status").lower()
        if status not in VALIDATION_EVIDENCE_STATUSES:
            raise ValueError(f"invalid validation evidence status: {self.status}")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "provider", required_text(self.provider, "provider"))
        object.__setattr__(self, "execution_ref", optional_text(self.execution_ref, "execution_ref"))
        if self.telemetry_observed is not None and not isinstance(self.telemetry_observed, bool):
            raise ValueError("telemetry_observed must be a bool or None")
        if self.detection_observed is not None and not isinstance(self.detection_observed, bool):
            raise ValueError("detection_observed must be a bool or None")
        object.__setattr__(self, "telemetry_refs", normalize_refs(self.telemetry_refs, "telemetry_refs"))
        object.__setattr__(self, "alert_refs", normalize_refs(self.alert_refs, "alert_refs"))
        object.__setattr__(self, "latency_ms", non_negative_int(self.latency_ms, "latency_ms"))
        object.__setattr__(self, "started_at", optional_text(self.started_at, "started_at"))
        object.__setattr__(self, "completed_at", optional_text(self.completed_at, "completed_at"))
        object.__setattr__(self, "provenance", normalize_refs(self.provenance, "provenance"))

    def to_dict(self):
        return {
            "id": self.id,
            "validation_contract_id": self.validation_contract_id,
            "detection_artifact_id": self.detection_artifact_id,
            "artifact_version": self.artifact_version,
            "telemetry_contract_id": self.telemetry_contract_id,
            "telemetry_contract_version": self.telemetry_contract_version,
            "status": self.status,
            "provider": self.provider,
            "execution_ref": self.execution_ref,
            "telemetry_observed": self.telemetry_observed,
            "telemetry_refs": list(self.telemetry_refs),
            "detection_observed": self.detection_observed,
            "alert_refs": list(self.alert_refs),
            "latency_ms": self.latency_ms,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "provenance": list(self.provenance),
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("validation evidence must be a mapping")
        return cls(
            id=value.get("id"),
            validation_contract_id=value.get("validation_contract_id"),
            detection_artifact_id=value.get("detection_artifact_id"),
            artifact_version=value.get("artifact_version"),
            telemetry_contract_id=value.get("telemetry_contract_id"),
            telemetry_contract_version=value.get("telemetry_contract_version"),
            status=value.get("status"),
            provider=value.get("provider"),
            execution_ref=value.get("execution_ref"),
            telemetry_observed=value.get("telemetry_observed"),
            telemetry_refs=value.get("telemetry_refs") or (),
            detection_observed=value.get("detection_observed"),
            alert_refs=value.get("alert_refs") or (),
            latency_ms=value.get("latency_ms"),
            started_at=value.get("started_at"),
            completed_at=value.get("completed_at"),
            provenance=value.get("provenance") or (),
        )


__all__ = ["VALIDATION_EVIDENCE_STATUSES", "ValidationEvidence", "ValidationEvidenceStatus"]
