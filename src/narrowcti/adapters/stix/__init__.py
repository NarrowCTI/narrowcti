"""Generic STIX 2.1 serialization primitives.

This package intentionally has no OpenCTI, gateway, source-adapter or
GraphQL knowledge.  Platform-specific STIX profiles live under their owning
adapter package.
"""

from .identifiers import (
    deterministic_graph_object_id,
    deterministic_identity_id,
    deterministic_report_id,
)
from .patterns import escape_pattern_value, indicator_pattern
from .serializer import build_indicators, build_report_bundle, build_stix_report

__all__ = [
    "build_indicators",
    "build_report_bundle",
    "build_stix_report",
    "deterministic_graph_object_id",
    "deterministic_identity_id",
    "deterministic_report_id",
    "escape_pattern_value",
    "indicator_pattern",
]
