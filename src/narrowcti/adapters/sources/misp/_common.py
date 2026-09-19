from __future__ import annotations

from collections.abc import Mapping



def compact_mapping(value):
    return dict(value) if isinstance(value, Mapping) else {}

def list_values(value):
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return []

def attribute_tags(attribute):
    tags = []
    for tag in list_values(attribute.get("Tag")):
        if isinstance(tag, Mapping):
            value = tag.get("name") or tag.get("Name")
        else:
            value = tag
        if value:
            tags.append(value)
    return tags

def flatten_text(value):
    if value is None:
        return []
    if isinstance(value, Mapping):
        values = []
        for item in value.values():
            values.extend(flatten_text(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(flatten_text(item))
        return values
    return [value]

def clean_text(value):
    return " ".join(str(value or "").strip().split())

def is_truthy(value):
    if value is True:
        return True
    return clean_text(value).casefold() in {"1", "true", "yes"}

def unique_text_values(values):
    seen = set()
    result = []
    for value in values or []:
        text = clean_text(value)
        key = text.casefold()
        if not text or key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result

def event_tag_names(value):
    value = compact_mapping(value)
    raw_tags = value.get("Tag") or value.get("tags")
    return unique_text_values(
        [
            tag.get("name") or tag.get("Name")
            if isinstance(tag, Mapping)
            else tag
            for tag in list_values(raw_tags)
        ]
    )
