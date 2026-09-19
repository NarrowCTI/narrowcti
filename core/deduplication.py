"""Compatibility wrapper for the canonical local artifact index."""

from narrowcti.adapters.persistence.local.artifact_index import (
    ARTIFACT_RECORDS_KEY,
    ARTIFACTS_KEY,
    ArtifactDeduplicationIndex,
    LOWERCASE_VALUE_TYPES,
    TYPE_ALIASES,
    default_artifact_state,
    indicator_fingerprint,
    load_artifact_state,
    normalize_artifact_state,
    normalize_indicator_type,
    normalize_indicator_value,
    save_artifact_state,
    source_sighting_key,
    utc_now,
)

__all__ = [
    "ARTIFACTS_KEY",
    "ARTIFACT_RECORDS_KEY",
    "ArtifactDeduplicationIndex",
    "LOWERCASE_VALUE_TYPES",
    "TYPE_ALIASES",
    "default_artifact_state",
    "indicator_fingerprint",
    "load_artifact_state",
    "normalize_artifact_state",
    "normalize_indicator_type",
    "normalize_indicator_value",
    "save_artifact_state",
    "source_sighting_key",
    "utc_now",
]
