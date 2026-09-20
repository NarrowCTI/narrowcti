"""Compatibility surface for the canonical OpenCTI client adapter."""

from narrowcti.adapters.opencti.client import (
    ABOUT_QUERY,
    LEGACY_OPENCTI_PREFIXES,
    PYCTI7_INPUT_FIELDS,
    PYCTI7_QUERY_INPUTS,
    NarrowCTIOpenCTIApiClient,
    OpenCTICompatibilityError,
    build_opencti_client,
    sanitize_legacy_query,
    sanitize_legacy_variables,
)

__all__ = [
    "ABOUT_QUERY", "LEGACY_OPENCTI_PREFIXES", "PYCTI7_INPUT_FIELDS", "PYCTI7_QUERY_INPUTS",
    "NarrowCTIOpenCTIApiClient", "OpenCTICompatibilityError", "build_opencti_client",
    "sanitize_legacy_query", "sanitize_legacy_variables",
]
