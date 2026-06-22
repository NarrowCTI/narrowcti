import re
from urllib.parse import urlparse


ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


ENTITY_SPECS = (
    ("adversaries", "adversary", "threat_actor", 60),
    ("malware_families", "malware_families", "malware", 55),
    ("attack_ids", "attack_ids", "attack_pattern", 70),
    ("industries", "industries", "target_sector", 50),
    ("targeted_countries", "targeted_countries", "target_country", 50),
    ("tags", "tags", "tag", 35),
)


def extract_otx_entities(pulse):
    pulse = pulse or {}
    entities = {
        "adversaries": normalize_values(pulse.get("adversary")),
        "malware_families": normalize_values(pulse.get("malware_families")),
        "attack_ids": normalize_attack_ids(pulse.get("attack_ids")),
        "industries": normalize_values(pulse.get("industries")),
        "targeted_countries": normalize_values(pulse.get("targeted_countries")),
        "tlp": normalize_tlp(pulse),
        "references": normalize_references(pulse.get("references")),
        "tags": normalize_values(pulse.get("tags")),
    }
    entities["records"] = extraction_records(entities)
    entities["counts"] = {
        key: len(value)
        for key, value in entities.items()
        if key != "records" and isinstance(value, list)
    }
    return entities


def normalize_values(value):
    values = []
    for item in flatten(value):
        normalized = normalize_value(item)
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def normalize_attack_ids(value):
    attack_ids = []
    for item in flatten(value):
        for match in ATTACK_ID_PATTERN.findall(str(item or "")):
            normalized = match.upper()
            if normalized not in attack_ids:
                attack_ids.append(normalized)
    return attack_ids


def normalize_tlp(pulse):
    values = normalize_values(
        pulse.get("TLP")
        or pulse.get("tlp")
        or pulse.get("tlp_marking")
        or pulse.get("marking"),
    )
    normalized = []
    for value in values:
        clean = value.lower().replace("tlp:", "").strip()
        if clean and clean not in normalized:
            normalized.append(clean)
    return normalized


def normalize_references(value):
    references = []
    for item in flatten(value):
        reference = normalize_reference(item)
        if reference and reference not in references:
            references.append(reference)
    return references


def normalize_reference(value):
    if isinstance(value, dict):
        url = normalize_value(value.get("url") or value.get("link") or value.get("href"))
        name = normalize_value(
            value.get("source_name")
            or value.get("name")
            or value.get("title")
            or domain_from_url(url)
        )
    else:
        url = normalize_value(value)
        name = domain_from_url(url)
    if not url and not name:
        return {}
    return {
        "url": url,
        "source_name": name or url,
    }


def extraction_records(entities):
    records = []
    for key, source_field, entity_type, confidence in ENTITY_SPECS:
        for value in entities.get(key) or []:
            records.append(
                {
                    "entity_type": entity_type,
                    "value": value,
                    "source_field": source_field,
                    "confidence": confidence,
                }
            )
    for value in entities.get("tlp") or []:
        records.append(
            {
                "entity_type": "marking",
                "value": value,
                "source_field": "TLP",
                "confidence": 80,
            }
        )
    for reference in entities.get("references") or []:
        records.append(
            {
                "entity_type": "external_reference",
                "value": reference.get("url") or reference.get("source_name"),
                "source_field": "references",
                "confidence": 50,
            }
        )
    return records


def flatten(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(flatten(item))
        return values
    if isinstance(value, str) and "," in value:
        return [item for item in value.split(",")]
    return [value]


def normalize_value(value):
    if isinstance(value, dict):
        value = (
            value.get("name")
            or value.get("value")
            or value.get("id")
            or value.get("url")
            or value.get("title")
        )
    normalized = str(value or "").strip()
    return " ".join(normalized.split())


def domain_from_url(value):
    parsed = urlparse(value or "")
    return parsed.netloc or ""
