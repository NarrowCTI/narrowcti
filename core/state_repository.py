"""Compatibility wrapper for local processed-item repositories."""

from narrowcti.adapters.persistence.local.state_repository import (
    DEFAULT_STATE_KEY,
    MISPEventStateRepository,
    ProcessedItemStateRepository,
    PulseStateRepository,
    load_state,
    save_state,
)

__all__ = [
    "DEFAULT_STATE_KEY",
    "MISPEventStateRepository",
    "ProcessedItemStateRepository",
    "PulseStateRepository",
    "load_state",
    "save_state",
]
