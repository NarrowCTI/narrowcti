"""Detection lifecycle vocabulary and pure adjacent-transition rules."""

from __future__ import annotations

from typing import Literal

from ._normalization import required_text


DETECTION_LIFECYCLE_STATES = (
    "proposed",
    "reviewed",
    "designed",
    "compiled",
    "telemetry-verified",
    "deployed",
    "tested",
    "validated",
    "degraded",
    "retired",
)
DetectionLifecycleState = Literal[
    "proposed",
    "reviewed",
    "designed",
    "compiled",
    "telemetry-verified",
    "deployed",
    "tested",
    "validated",
    "degraded",
    "retired",
]

_ALLOWED_TRANSITIONS = {
    "proposed": {"reviewed"},
    "reviewed": {"designed"},
    "designed": {"compiled"},
    "compiled": {"telemetry-verified"},
    "telemetry-verified": {"deployed"},
    "deployed": {"tested"},
    "tested": {"validated"},
    "validated": {"degraded"},
    "degraded": {"retired"},
    "retired": set(),
}


def normalize_lifecycle(value):
    normalized = required_text(value, "lifecycle").lower()
    if normalized not in DETECTION_LIFECYCLE_STATES:
        raise ValueError(f"invalid detection lifecycle state: {value}")
    return normalized


def can_transition(current, target):
    try:
        current_state = normalize_lifecycle(current)
        target_state = normalize_lifecycle(target)
    except ValueError:
        return False
    return target_state in _ALLOWED_TRANSITIONS[current_state]


def transition_lifecycle(current, target):
    current_state = normalize_lifecycle(current)
    target_state = normalize_lifecycle(target)
    if not can_transition(current_state, target_state):
        raise ValueError(
            f"invalid detection lifecycle transition: {current_state} -> {target_state}"
        )
    return target_state


__all__ = [
    "DETECTION_LIFECYCLE_STATES",
    "DetectionLifecycleState",
    "can_transition",
    "normalize_lifecycle",
    "transition_lifecycle",
]
