from __future__ import annotations

import re
from collections.abc import Mapping

try:
    import yaml
except Exception:
    yaml = None

try:
    from sigma.parser.collection import SigmaCollectionParser
except Exception:
    SigmaCollectionParser = None

from ._common import (
    attribute_tags,
    clean_text,
    compact_mapping,
    flatten_text,
    event_tag_names,
    is_truthy,
    list_values,
    unique_text_values,
)



ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

ATTACK_ID_PATH_PATTERN = re.compile(r"\b(T\d{4})[/.](\d{3})\b", re.IGNORECASE)

DETECTION_RULE_TYPES = {"yara", "sigma", "snort", "suricata", "pcre"}



def extract_misp_detection_rules(event):
    event = compact_mapping(event)
    rules = []
    for source in misp_detection_rule_sources(event):
        normalized = normalize_misp_detection_rule(source)
        if normalized:
            rules.append(normalized)
    return deduplicate_misp_detection_rules(rules)

def misp_detection_rule_sources(event):
    event = compact_mapping(event)
    sources = []
    event_tags = event_tag_names(event)
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
                "event_tags": event_tags,
                "object_tags": [],
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                    "event_tags": event_tags,
                    "object_tags": event_tag_names(misp_object),
                }
            )
    return sources

def normalize_misp_detection_rule(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    rule_type = misp_detection_rule_type(attribute, misp_object)
    raw_rule_content = str(attribute.get("value") or "").strip()
    rule_content = raw_rule_content.strip()
    if rule_type not in DETECTION_RULE_TYPES:
        return {}
    if not clean_text(rule_content) or is_truthy(attribute.get("deleted")):
        return {}
    opencti_indicator_compatible = True
    compatibility_reason = ""
    if rule_type == "sigma":
        (
            opencti_indicator_compatible,
            compatibility_reason,
        ) = sigma_rule_opencti_compatibility(rule_content)
    title = detection_rule_title(rule_type, raw_rule_content, attribute)
    tags = unique_text_values(
        attribute_tags(attribute)
        + list_values(source.get("object_tags"))
        + list_values(source.get("event_tags"))
    )
    attack_ids, attack_id_source = detection_rule_attack_ids(
        rule_type,
        rule_content,
        tags,
    )
    return compact_mapping(
        {
            "value": title,
            "rule_type": rule_type,
            "pattern_type": rule_type,
            "pattern": rule_content,
            "opencti_indicator_compatible": opencti_indicator_compatible,
            "opencti_indicator_compatibility_reason": compatibility_reason,
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "first_seen": attribute.get("first_seen"),
            "last_seen": attribute.get("last_seen"),
            "tags": tags,
            "attack_pattern_ids": attack_ids,
            "attack_id_source": attack_id_source,
            "source_field": source.get("source_field"),
        }
    )

def detection_rule_attack_ids(rule_type, rule_content, tags):
    """Return ATT&CK IDs only when a rule contains an explicit mapping."""
    ids = []
    source = ""

    for value in tags or []:
        for normalized in attack_ids_from_text(value):
            if normalized not in ids:
                ids.append(normalized)
    if ids:
        source = "misp-tags"

    if rule_type == "sigma":
        explicit_values = sigma_explicit_mapping_values(rule_content)
        for value in explicit_values:
            for normalized in attack_ids_from_text(value):
                if normalized not in ids:
                    ids.append(normalized)
        if explicit_values and ids and not source:
            source = "sigma-tags-or-references"
        elif explicit_values and ids:
            source = f"{source}+sigma-tags-or-references"

    return normalize_attack_ids(ids), source

def attack_ids_from_text(value):
    text = clean_text(value)
    ids = [match.upper() for match in ATTACK_ID_PATTERN.findall(text)]
    ids.extend(
        f"{parent.upper()}.{subtechnique}"
        for parent, subtechnique in ATTACK_ID_PATH_PATTERN.findall(text)
    )
    return unique_text_values(ids)

def normalize_attack_ids(values):
    """Prefer a referenced sub-technique over its parent path component."""
    normalized = unique_text_values(values)
    subtechnique_parents = {
        value.split(".", 1)[0].casefold()
        for value in normalized
        if "." in value
    }
    return [
        value
        for value in normalized
        if "." in value or value.casefold() not in subtechnique_parents
    ]

def sigma_explicit_mapping_values(rule_content):
    """Extract Sigma tags/references, never arbitrary description text."""
    content = str(rule_content or "").strip()
    if not content:
        return []
    values = []
    if yaml:
        try:
            parsed = yaml.safe_load(content)
        except Exception:
            parsed = None
        if isinstance(parsed, Mapping):
            for field in ("tags", "references"):
                values.extend(flatten_text(parsed.get(field)))
            return values

    active_field = ""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        field_match = re.match(r"^(tags|references)\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if field_match:
            active_field = field_match.group(1).casefold()
            inline = field_match.group(2).strip()
            if inline:
                values.append(inline)
            continue
        if active_field and (stripped.startswith("-") or line.startswith(" ")):
            values.append(stripped.lstrip("- ").strip())
            continue
        active_field = ""
    return values

def misp_detection_rule_type(attribute, misp_object):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    attribute_type = clean_text(attribute.get("type")).casefold()
    object_relation = clean_text(attribute.get("object_relation")).casefold()
    object_name = clean_text(misp_object.get("name")).casefold()
    if object_relation in DETECTION_RULE_TYPES:
        return object_relation
    if attribute_type not in DETECTION_RULE_TYPES:
        return ""
    if object_name in DETECTION_RULE_TYPES:
        return object_name
    return attribute_type

def detection_rule_title(rule_type, rule_content, attribute):
    comment = clean_text(attribute.get("comment"))
    if comment:
        return comment

    extracted = extract_detection_rule_name(rule_type, rule_content)
    if extracted:
        return extracted

    return "detection rule"

def extract_detection_rule_name(rule_type, rule_content):
    if rule_type == "sigma":
        match = re.search(r"(?im)^\s*title\s*:\s*(.+?)\s*$", rule_content)
        if match:
            return clean_text(match.group(1).strip("'\""))

    if rule_type == "yara":
        match = re.search(
            r"(?im)^\s*(?:private\s+)?rule\s+([A-Za-z0-9_.$-]+)",
            rule_content,
        )
        if match:
            return clean_text(match.group(1))

    if rule_type in {"snort", "suricata"}:
        match = re.search(r'msg\s*:\s*"([^"]+)"', rule_content, flags=re.IGNORECASE)
        if match:
            return clean_text(match.group(1))

    return ""

def sigma_rule_has_valid_shape(rule_content):
    compatible, _reason = sigma_rule_opencti_compatibility(rule_content)
    return compatible

def sigma_rule_opencti_compatibility(rule_content):
    content = str(rule_content or "").strip()
    if not content:
        return False, "empty sigma rule"
    if yaml:
        try:
            parsed = yaml.safe_load(content)
        except Exception:
            return False, "invalid sigma yaml"
        if not isinstance(parsed, Mapping):
            return False, "sigma yaml is not a mapping"
        if not clean_text(parsed.get("title")):
            return False, "missing title"
        logsource = parsed.get("logsource")
        if not isinstance(logsource, Mapping) or not compact_mapping(logsource):
            return False, "missing logsource"
        detection = parsed.get("detection")
        if not isinstance(detection, Mapping):
            return False, "missing detection mapping"
        if not clean_text(detection.get("condition")):
            return False, "missing detection condition"
        selections = [
            value
            for key, value in detection.items()
            if clean_text(key).casefold() != "condition"
            and value not in ("", None, [], {})
        ]
        if not selections:
            return False, "missing detection selection"
        return validate_sigma_with_opencti_parser(content)

    if not re.search(r"(?im)^\s*title\s*:", content):
        return False, "missing title"
    if not re.search(r"(?im)^\s*logsource\s*:", content):
        return False, "missing logsource"
    if not re.search(r"(?im)^\s*detection\s*:", content):
        return False, "missing detection"
    if not re.search(r"(?im)^\s*condition\s*:", content):
        return False, "missing detection condition"
    in_block_scalar = None
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if in_block_scalar is not None:
            if indent > in_block_scalar:
                continue
            in_block_scalar = None
        if stripped.startswith("- "):
            continue
        if ":" not in stripped:
            return False, "invalid yaml-like line"
        if stripped.endswith("|") or stripped.endswith(">"):
            in_block_scalar = indent
    return validate_sigma_with_opencti_parser(content)

def validate_sigma_with_opencti_parser(content):
    """Match the Sigma syntax gate used by the supported OpenCTI 6.9 runtime."""
    if SigmaCollectionParser is None:
        return False, "OpenCTI-compatible Sigma parser unavailable"
    try:
        SigmaCollectionParser(content)
    except Exception:
        return False, "rejected by OpenCTI-compatible Sigma parser"
    return True, ""

def deduplicate_misp_detection_rules(rules):
    seen = set()
    deduplicated = []
    for rule in rules:
        key = (
            str(rule.get("attribute_uuid", "")).casefold(),
            str(rule.get("rule_type", "")).casefold(),
            str(rule.get("pattern", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(rule)
    return deduplicated
