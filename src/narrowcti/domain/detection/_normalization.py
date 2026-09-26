"""Small immutable-value normalization helpers for detection contracts."""

from __future__ import annotations

from collections.abc import Iterable


def required_text(value, field_name):
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must be a non-empty string")
    return normalized


def optional_text(value, field_name):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    normalized = value.strip()
    return normalized or None


def normalize_refs(values, field_name):
    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    elif not isinstance(values, Iterable):
        raise ValueError(f"{field_name} must be an iterable of strings")
    result = []
    seen = set()
    for value in values:
        normalized = required_text(value, field_name)
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return tuple(result)


def positive_version(value, field_name="version"):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be an integer >= 1")
    return value


def confidence_value(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError("confidence must be None or an integer between 0 and 100")
    return value


def non_negative_int(value, field_name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be None or an integer >= 0")
    return value
