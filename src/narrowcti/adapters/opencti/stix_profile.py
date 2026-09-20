"""OpenCTI-specific STIX profile objects.

These conventions are serialized as STIX, but they are not generic STIX
semantics and therefore do not belong in ``adapters.stix``.
"""

from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from stix2 import ExtensionDefinition


OPENCTI_EXTENSION_DEFINITION_ID = (
    f"extension-definition--{uuid5(NAMESPACE_URL, 'opencti-extension-definition')}"
)
OPENCTI_CUSTOM_SDO_TYPES = {"channel", "event", "narrative"}


def _object_type(value) -> str:
    getter = getattr(value, "get", None)
    if callable(getter):
        return str(getter("type", "") or "").lower()
    return str(getattr(value, "type", "") or "").lower()


def opencti_extension_objects(graph_objects, identity_id: str, now: datetime):
    if not any(_object_type(item) in OPENCTI_CUSTOM_SDO_TYPES for item in graph_objects or []):
        return []
    return [
        ExtensionDefinition(
            id=OPENCTI_EXTENSION_DEFINITION_ID,
            name="OpenCTI",
            description="OpenCTI native custom SDO extension.",
            created=now,
            modified=now,
            created_by_ref=identity_id,
            schema="https://www.filigran.io/opencti/schema",
            version="1.0",
            extension_types=["new-sdo"],
            allow_custom=True,
        )
    ]


__all__ = [
    "OPENCTI_CUSTOM_SDO_TYPES",
    "OPENCTI_EXTENSION_DEFINITION_ID",
    "opencti_extension_objects",
]
