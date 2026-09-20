"""Compatibility surface for the canonical OpenCTI artifact adapter."""

from narrowcti.adapters.opencti.deduplication import (
    INDICATOR_LOOKUP_QUERY,
    CompositeArtifactDeduplication,
    OpenCTIArtifactLookup,
)

__all__ = [
    "INDICATOR_LOOKUP_QUERY",
    "CompositeArtifactDeduplication",
    "OpenCTIArtifactLookup",
]
