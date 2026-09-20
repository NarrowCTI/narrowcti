"""Deterministic STIX identifier policy.

The policy is intentionally kept at the STIX boundary.  Application code
uses semantic keys and does not need to depend on STIX identifier syntax.
"""

from __future__ import annotations

from collections.abc import Mapping
from uuid import NAMESPACE_URL, uuid5


IDENTITY_ID_NAMESPACE = "https://narrowcti.local/stix/identity"
GRAPH_OBJECT_ID_NAMESPACE = "https://narrowcti.local/stix/graph-object"


def _clean_string(value: object) -> str:
    return str(value).strip() if value is not None else ""


def deterministic_identity_id(name: object, identity_class: object = "organization") -> str:
    material = "|".join(
        (
            IDENTITY_ID_NAMESPACE,
            _clean_string(identity_class).casefold() or "organization",
            _clean_string(name).casefold() or "unknown",
        )
    )
    return f"identity--{uuid5(NAMESPACE_URL, material)}"


def deterministic_graph_object_id(
    stix_object_type: object,
    name: object,
    value: object = "",
    attributes: Mapping[str, object] | None = None,
) -> str:
    attributes = attributes if isinstance(attributes, Mapping) else {}
    object_type = _clean_string(stix_object_type).lower()
    identity_class = _clean_string(attributes.get("identity_class")).casefold()
    material = "|".join(
        (
            GRAPH_OBJECT_ID_NAMESPACE,
            object_type,
            identity_class,
            _clean_string(value or name).casefold(),
            _clean_string(name).casefold(),
        )
    )
    return f"{object_type}--{uuid5(NAMESPACE_URL, material)}"


def deterministic_report_id(name: object, description: object) -> str:
    material = "|".join(
        (
            "narrowcti-report",
            _clean_string(name).casefold(),
            _clean_string(description).casefold(),
        )
    )
    return f"report--{uuid5(NAMESPACE_URL, material)}"


__all__ = [
    "GRAPH_OBJECT_ID_NAMESPACE",
    "IDENTITY_ID_NAMESPACE",
    "deterministic_graph_object_id",
    "deterministic_identity_id",
    "deterministic_report_id",
]
