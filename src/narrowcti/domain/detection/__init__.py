"""Pure detection-engineering domain contracts."""

from .artifacts import DetectionArtifact
from .lifecycle import (
    DETECTION_LIFECYCLE_STATES,
    DetectionLifecycleState,
    can_transition,
    normalize_lifecycle,
    transition_lifecycle,
)
from .requirements import (
    DetectionBehavior,
    DetectionRequirement,
    DetectionScope,
    ThreatContext,
)
from .telemetry import (
    READINESS_STATES,
    TELEMETRY_FIELD_AVAILABILITIES,
    TelemetryContract,
    TelemetryField,
)

__all__ = [
    "DETECTION_LIFECYCLE_STATES",
    "DetectionArtifact",
    "DetectionBehavior",
    "DetectionLifecycleState",
    "DetectionRequirement",
    "DetectionScope",
    "READINESS_STATES",
    "TELEMETRY_FIELD_AVAILABILITIES",
    "TelemetryContract",
    "TelemetryField",
    "ThreatContext",
    "can_transition",
    "normalize_lifecycle",
    "transition_lifecycle",
]
