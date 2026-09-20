"""Generic STIX 2.1 serializer for standard reports and indicators.

Only standard STIX concepts live here.  OpenCTI custom SDOs, extensions and
native GraphQL mutations are owned by ``adapters.opencti``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from stix2 import Bundle, Identity, Indicator, Report

from .identifiers import (
    deterministic_identity_id,
    deterministic_report_id,
)
from .patterns import indicator_pattern


def _clean_string(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _parse_timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _clean_string(value)
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def source_publication_time(value: object, fallback: datetime) -> datetime:
    """Preserve the historical source-date fallback semantics."""

    return _parse_timestamp(value) or fallback


def build_identity(identity_name: str, identity_class: str = "organization") -> Identity:
    return Identity(
        id=deterministic_identity_id(identity_name, identity_class),
        name=identity_name,
        identity_class=identity_class,
    )


def build_indicators(raw_indicators, identity_id: str, score: int, valid_from: datetime):
    objects = []
    seen_patterns = set()

    for raw_indicator in raw_indicators:
        pattern = indicator_pattern(raw_indicator)
        if not pattern or pattern in seen_patterns:
            continue
        seen_patterns.add(pattern)
        value = raw_indicator.get("indicator")
        objects.append(
            Indicator(
                name=value,
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                confidence=score,
                created_by_ref=identity_id,
            )
        )
    return objects


def build_stix_report(
    name: str,
    description: str,
    score: int,
    now: datetime,
    identity_id: str,
    object_refs: list[str],
    source_date: object = None,
    published: datetime | None = None,
) -> Report:
    custom_properties: dict[str, Any] = {}
    if _clean_string(source_date):
        custom_properties["x_narrowcti_source_date"] = _clean_string(source_date)
    return Report(
        id=deterministic_report_id(name, description),
        name=name,
        description=description or "",
        report_types=["threat-report"],
        confidence=score,
        created=now,
        modified=now,
        published=published or now,
        created_by_ref=identity_id,
        object_refs=object_refs,
        custom_properties=custom_properties,
        allow_custom=True,
    )


def build_report_bundle(
    name: str,
    description: str,
    score: int,
    indicators=None,
    identity_name: str = "NarrowCTI Gateway",
    published_at=None,
):
    now = datetime.now(timezone.utc)
    publication_time = source_publication_time(published_at, now)
    identity = build_identity(identity_name)
    indicator_objects = build_indicators(
        indicators or [], identity.id, score, publication_time
    )
    object_refs = [indicator.id for indicator in indicator_objects] or [identity.id]
    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        object_refs,
        source_date=published_at,
        published=publication_time,
    )
    return Bundle(objects=[identity, *indicator_objects, report], allow_custom=True), len(
        indicator_objects
    )


__all__ = [
    "build_identity",
    "build_indicators",
    "build_report_bundle",
    "build_stix_report",
    "source_publication_time",
]
