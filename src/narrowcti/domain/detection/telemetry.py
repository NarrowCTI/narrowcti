"""Manual telemetry readiness contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

from ._normalization import normalize_refs, positive_version, required_text
from .requirements import DetectionScope


TELEMETRY_FIELD_AVAILABILITIES = ("available", "missing", "unknown")
TelemetryFieldAvailability = Literal["available", "missing", "unknown"]
READINESS_STATES = ("ready", "incomplete", "unknown")


@dataclass(frozen=True)
class TelemetryField:
    name: str
    availability: TelemetryFieldAvailability

    def __post_init__(self):
        object.__setattr__(self, "name", required_text(self.name, "field name"))
        availability = required_text(self.availability, "field availability").lower()
        if availability not in TELEMETRY_FIELD_AVAILABILITIES:
            raise ValueError(f"invalid telemetry field availability: {self.availability}")
        object.__setattr__(self, "availability", availability)


def _normalize_fields(required_fields):
    if required_fields is None:
        return ()
    if isinstance(required_fields, Mapping):
        values = [TelemetryField(name, availability) for name, availability in required_fields.items()]
    else:
        values = []
        for field in required_fields:
            if isinstance(field, TelemetryField):
                values.append(field)
            elif isinstance(field, Mapping):
                values.append(TelemetryField(field.get("name"), field.get("availability")))
            else:
                raise ValueError("required_fields must contain TelemetryField values")
    by_name = {}
    for field in values:
        if field.name in by_name and by_name[field.name] != field:
            raise ValueError(f"conflicting telemetry field declaration: {field.name}")
        by_name[field.name] = field
    return tuple(by_name[name] for name in sorted(by_name))


@dataclass(frozen=True)
class TelemetryContract:
    id: str
    scope: DetectionScope
    provider: str
    capability: str
    schema_version: str
    required_fields: tuple[TelemetryField, ...] = ()
    blocks: tuple[str, ...] = ()
    version: int = 1

    def __post_init__(self):
        object.__setattr__(self, "id", required_text(self.id, "id"))
        if not isinstance(self.scope, DetectionScope):
            raise ValueError("scope must be a DetectionScope")
        object.__setattr__(self, "provider", required_text(self.provider, "provider"))
        object.__setattr__(self, "capability", required_text(self.capability, "capability"))
        object.__setattr__(self, "schema_version", required_text(self.schema_version, "schema_version"))
        object.__setattr__(self, "required_fields", _normalize_fields(self.required_fields))
        object.__setattr__(self, "blocks", normalize_refs(self.blocks, "blocks"))
        object.__setattr__(self, "version", positive_version(self.version))

    @property
    def readiness(self):
        if not self.required_fields:
            return "unknown"
        availability = {field.availability for field in self.required_fields}
        if "missing" in availability:
            return "incomplete"
        if "unknown" in availability:
            return "unknown"
        return "ready"

    def to_dict(self):
        return {
            "id": self.id,
            "scope": self.scope.to_dict(),
            "provider": self.provider,
            "capability": self.capability,
            "schema_version": self.schema_version,
            "required_fields": {
                field.name: field.availability for field in self.required_fields
            },
            "readiness": self.readiness,
            "blocks": list(self.blocks),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise ValueError("telemetry contract must be a mapping")
        contract = cls(
            id=value.get("id"),
            scope=DetectionScope.from_dict(value.get("scope") or {}),
            provider=value.get("provider"),
            capability=value.get("capability"),
            schema_version=value.get("schema_version"),
            required_fields=value.get("required_fields") or {},
            blocks=value.get("blocks") or (),
            version=value.get("version", 1),
        )
        supplied_readiness = value.get("readiness")
        if supplied_readiness is not None and supplied_readiness != contract.readiness:
            raise ValueError(
                f"telemetry readiness disagrees with required_fields: {supplied_readiness}"
            )
        return contract


__all__ = [
    "READINESS_STATES",
    "TELEMETRY_FIELD_AVAILABILITIES",
    "TelemetryContract",
    "TelemetryField",
    "TelemetryFieldAvailability",
]
