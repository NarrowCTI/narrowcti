import re
from collections.abc import Mapping

GRAPH_EVIDENCE_VERSION = "v1.0.0"

ENTITY_TARGETS = {
    "campaign": ("campaign", "related-to"),
    "course_of_action": ("course-of-action", "related-to"),
    "threat_actor": ("threat-actor", "attributed-to"),
    "threat_actor_individual": ("threat-actor", "attributed-to"),
    "intrusion_set": ("intrusion-set", "attributed-to"),
    "infrastructure": ("infrastructure", "uses"),
    "autonomous_system": ("autonomous-system", "related-to"),
    "channel": ("channel", "uses"),
    "event": ("event", "related-to"),
    "malware": ("malware", "uses"),
    "narrative": ("narrative", "related-to"),
    "security_platform": ("security-platform", "related-to"),
    "tool": ("tool", "uses"),
    "vulnerability": ("vulnerability", "related-to"),
    "observable": ("observable", "based-on"),
    "attack_pattern": ("attack-pattern", "uses"),
    "attack_tactic": ("x-mitre-tactic", "uses"),
    "target_sector": ("identity", "targets"),
    "target_organization": ("identity", "targets"),
    "target_individual": ("identity", "targets"),
    "target_system": ("identity", "targets"),
    "target_administrative_area": ("location", "targets"),
    "target_city": ("location", "targets"),
    "target_country": ("location", "targets"),
    "target_position": ("location", "targets"),
    "target_region": ("location", "targets"),
    "source_identity": ("identity", "originated-from"),
    "collector": ("identity", "collected-by"),
    "tag": ("label", "labels"),
    "marking": ("marking-definition", "marked-with"),
    "external_reference": ("external-reference", "references"),
    "detection_rule": ("indicator", "detects"),
    "attack_platform": ("x-narrowcti-attack-platform", "applies-to"),
    "attack_data_source": ("x-mitre-data-source", "detects"),
    "attack_data_component": ("x-mitre-data-component", "detects"),
    "detection_guidance": ("note", "documents"),
    "event_report": ("note", "documents"),
    "sighting": ("sighting", "sighting-of"),
    "object_reference": ("relationship", "related-to"),
}

TARGET_SECTOR_ALIASES = {
    "aerospace and defense": "Defense",
    "banking": "Finance",
    "banking and finance": "Finance",
    "defence": "Defense",
    "defense industrial base": "Defense",
    "e-commerce": "Retail",
    "financial": "Finance",
    "financial sector": "Finance",
    "financial services": "Finance",
    "fintech": "Finance",
    "government and public sector": "Government",
    "health": "Healthcare",
    "health care": "Healthcare",
    "healthcare and public health": "Healthcare",
    "information technology": "Technology",
    "it": "Technology",
    "oil and gas": "Energy",
    "public sector": "Government",
    "telecom": "Telecommunications",
    "telecommunications": "Telecommunications",
    "transport": "Transportation",
}

TARGET_COUNTRY_ALIASES = {
    "ar": "Argentina",
    "arg": "Argentina",
    "br": "Brazil",
    "bra": "Brazil",
    "cn": "China",
    "de": "Germany",
    "fr": "France",
    "gb": "United Kingdom",
    "ir": "Iran",
    "iran, islamic republic of": "Iran",
    "kp": "North Korea",
    "kr": "South Korea",
    "ru": "Russia",
    "russian federation": "Russia",
    "uk": "United Kingdom",
    "us": "United States",
    "usa": "United States",
    "u.s.": "United States",
    "u.s.a.": "United States",
    "united states of america": "United States",
}

TARGET_REGION_ALIASES = {
    "apac": "Asia-Pacific",
    "asia pacific": "Asia-Pacific",
    "asia-pacific": "Asia-Pacific",
    "cis": "Commonwealth of Independent States",
    "emea": "Europe, Middle East and Africa",
    "eu": "Europe",
    "european union": "Europe",
    "latam": "Latin America",
    "latin america and caribbean": "Latin America",
    "mena": "Middle East and North Africa",
    "middle east": "Middle East",
    "north america": "North America",
    "south america": "South America",
}

INTRUSION_SET_ALIASES = {
    "hidden cobra": "Lazarus Group",
    "lazarus": "Lazarus Group",
    "lazarus group": "Lazarus Group",
    "palmerworm": "BlackTech",
}

MALWARE_ALIASES = {
    "lumma c2": "Lumma Stealer",
    "lummac2": "Lumma Stealer",
    "lumma stealer": "Lumma Stealer",
    "lummastealer": "Lumma Stealer",
}

ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

TARGET_LOCATION_ENTITY_TYPES = {
    "target_administrative_area",
    "target_city",
    "target_country",
    "target_position",
    "target_region",
}

def evidence_record(
    entity_type,
    value,
    source_key="",
    source_name="",
    source_field="",
    confidence=50,
    display_name="",
    attributes=None,
    stix_object_type="",
    relationship_type="",
):
    entity_type = clean_string(entity_type)
    value = clean_string(value)
    compact_attributes = compact_mapping(attributes)
    value, compact_attributes = normalize_evidence_value(
        entity_type,
        value,
        compact_attributes,
    )
    if not entity_type or not value:
        return {}

    default_stix_object_type, default_relationship_type = ENTITY_TARGETS.get(
        entity_type,
        ("x-narrowcti-evidence", "related-to"),
    )
    stix_object_type = clean_string(stix_object_type) or default_stix_object_type
    relationship_type = clean_string(relationship_type) or default_relationship_type
    record = {
        "entity_type": entity_type,
        "value": value,
        "stix_object_type": stix_object_type,
        "relationship_type": relationship_type,
        "source_key": clean_string(source_key),
        "source_name": clean_string(source_name),
        "source_field": clean_string(source_field),
        "confidence": evidence_confidence(
            entity_type,
            confidence,
            source_name,
            source_field,
            compact_attributes,
        ),
    }
    display_name = clean_string(display_name)
    if display_name and display_name != value:
        record["display_name"] = display_name
    if compact_attributes:
        record["attributes"] = compact_attributes
    return record

def evidence_confidence(entity_type, confidence, source_name="", source_field="", attributes=None):
    confidence = clamp_confidence(confidence)
    if entity_type == "target_sector":
        return target_sector_confidence(confidence, source_name, source_field, attributes)
    if entity_type in TARGET_LOCATION_ENTITY_TYPES:
        return target_location_confidence(confidence, source_name, source_field)
    if entity_type == "intrusion_set":
        return intrusion_set_confidence(confidence, attributes)
    if entity_type == "malware":
        return malware_confidence(confidence, attributes)
    return confidence

def target_sector_confidence(confidence, source_name="", source_field="", attributes=None):
    source_name = clean_string(source_name).casefold()
    source_field = clean_string(source_field).casefold()
    attributes = compact_mapping(attributes)
    if source_name == "misp-galaxy" and "targeted-sector" in source_field:
        return max(confidence, 75)
    if source_name == "otx" and source_field == "industries":
        return max(confidence, 60)
    if attributes.get("normalized_value"):
        return max(confidence, 60)
    return confidence

def target_location_confidence(confidence, source_name="", source_field=""):
    source_name = clean_string(source_name).casefold()
    source_field = clean_string(source_field).casefold()
    if source_name == "misp-galaxy" and "targeted-" in source_field:
        return max(confidence, 70)
    if source_name == "otx" and source_field.startswith("targeted_"):
        return max(confidence, 60)
    return confidence

def intrusion_set_confidence(confidence, attributes=None):
    attributes = compact_mapping(attributes)
    if attributes.get("normalized_value"):
        return max(confidence, 70)
    return confidence

def malware_confidence(confidence, attributes=None):
    attributes = compact_mapping(attributes)
    if attributes.get("normalized_value"):
        return max(confidence, 70)
    return confidence

def normalize_evidence_value(entity_type, value, attributes):
    if entity_type == "intrusion_set":
        return normalize_alias_value(
            value,
            attributes,
            INTRUSION_SET_ALIASES,
            "intrusion_set",
        )
    if entity_type == "malware":
        return normalize_alias_value(
            value,
            attributes,
            MALWARE_ALIASES,
            "malware",
        )
    if entity_type == "target_sector":
        return normalize_alias_value(
            value,
            attributes,
            TARGET_SECTOR_ALIASES,
            "target_sector",
        )
    if entity_type == "target_country":
        return normalize_alias_value(
            value,
            attributes,
            TARGET_COUNTRY_ALIASES,
            "target_country",
        )
    if entity_type == "target_region":
        return normalize_alias_value(
            value,
            attributes,
            TARGET_REGION_ALIASES,
            "target_region",
        )
    return value, attributes

def normalize_alias_value(value, attributes, aliases, scope):
    canonical = aliases.get(value.casefold(), value)
    if canonical == value:
        return value, attributes
    attributes = dict(attributes)
    attributes.setdefault("source_value", value)
    attributes["normalized_value"] = True
    attributes["normalization_scope"] = scope
    return canonical, compact_mapping(attributes)

def compact_mapping(value):
    if not isinstance(value, Mapping):
        return {}
    return {
        clean_string(key): item
        for key, item in value.items()
        if clean_string(key) and item not in ("", None, [], {})
    }

def clean_string(value):
    return " ".join(str(value or "").strip().split())

def clean_values(values):
    return [clean_string(value) for value in values or [] if clean_string(value)]

def flatten_values(value):
    if isinstance(value, Mapping):
        flattened = []
        for item in value.values():
            flattened.extend(flatten_values(item))
        return flattened
    if isinstance(value, (list, tuple, set)):
        flattened = []
        for item in value:
            flattened.extend(flatten_values(item))
        return flattened
    return [value] if value not in ("", None, [], {}) else []

def clamp_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))

def first_confidence_value(*values):
    for value in values:
        clean = clean_string(value)
        if clean:
            return clamp_confidence(clean)
    return 50
