import re
from urllib.parse import urlparse


ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
DETECTION_RULE_TYPES = {"yara"}
OBSERVABLE_TYPE_MAP = {
    "ipv4": "ipv4-addr",
    "ipv4-addr": "ipv4-addr",
    "ip": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "ipv6-addr": "ipv6-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "url": "url",
    "uri": "url",
    "email": "email-addr",
    "email-addr": "email-addr",
    "filehash-md5": "file",
    "md5": "file",
    "filehash-sha1": "file",
    "sha1": "file",
    "filehash-sha256": "file",
    "sha256": "file",
}
FILE_HASH_ALGORITHMS = {
    "filehash-md5": "MD5",
    "md5": "MD5",
    "filehash-sha1": "SHA-1",
    "sha1": "SHA-1",
    "filehash-sha256": "SHA-256",
    "sha256": "SHA-256",
}


ENTITY_SPECS = (
    ("adversaries", "adversary", "threat_actor", 60),
    ("malware_families", "malware_families", "malware", 55),
    ("attack_ids", "attack_ids", "attack_pattern", 70),
    ("vulnerabilities", "vulnerabilities", "vulnerability", 75),
    ("industries", "industries", "target_sector", 50),
    ("targeted_countries", "targeted_countries", "target_country", 50),
    ("authors", "author", "source_identity", 60),
    ("tags", "tags", "tag", 35),
)


def extract_otx_entities(pulse):
    pulse = pulse or {}
    entities = {
        "adversaries": normalize_values(pulse.get("adversary")),
        "malware_families": normalize_values(pulse.get("malware_families")),
        "attack_ids": normalize_attack_ids(pulse.get("attack_ids")),
        "vulnerabilities": normalize_cve_ids(cve_sources(pulse)),
        "industries": normalize_values(pulse.get("industries")),
        "targeted_countries": normalize_values(
            pulse.get("targeted_countries") or pulse.get("target_countries")
        ),
        "authors": normalize_authors(author_sources(pulse)),
        "lifecycle": pulse_lifecycle(pulse),
        "vote_summary": pulse_vote_summary(pulse),
        "indicator_observation_window": indicator_observation_window(
            pulse.get("indicators")
        ),
        "observables": otx_observables(pulse),
        "detection_rules": otx_detection_rules(pulse),
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


def normalize_authors(value):
    authors = []
    for item in flatten(value):
        normalized = normalize_author_value(item)
        if normalized and normalized not in authors:
            authors.append(normalized)
    return authors


def normalize_author_value(value):
    if isinstance(value, dict):
        value = (
            value.get("name")
            or value.get("display_name")
            or value.get("username")
            or value.get("user_name")
            or value.get("email")
            or value.get("title")
        )
    normalized = normalize_value(value)
    if normalized.isdigit():
        return ""
    return normalized


def normalize_attack_ids(value):
    attack_ids = []
    for item in flatten(value):
        for match in ATTACK_ID_PATTERN.findall(str(item or "")):
            normalized = match.upper()
            if normalized not in attack_ids:
                attack_ids.append(normalized)
    return attack_ids


def normalize_cve_ids(value):
    cve_ids = []
    for item in flatten_text(value):
        for match in CVE_ID_PATTERN.findall(str(item or "")):
            normalized = match.upper()
            if normalized not in cve_ids:
                cve_ids.append(normalized)
    return cve_ids


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


def cve_sources(pulse):
    values = [
        pulse.get("cve"),
        pulse.get("CVE"),
        pulse.get("cves"),
        pulse.get("vulnerability"),
        pulse.get("vulnerabilities"),
        pulse.get("targeted_vulnerabilities"),
        pulse.get("tags"),
        pulse.get("references"),
    ]
    for indicator in flatten(pulse.get("indicators")):
        if isinstance(indicator, dict):
            indicator_type = normalize_value(indicator.get("type")).lower()
            if "cve" in indicator_type or "vulnerab" in indicator_type:
                values.append(indicator)
        else:
            values.append(indicator)
    return values


def author_sources(pulse):
    return [
        pulse.get("author_name"),
        pulse.get("author"),
        pulse.get("created_by"),
        pulse.get("creator"),
        pulse.get("owner"),
        pulse.get("submitter"),
        pulse.get("user_name"),
        pulse.get("username"),
    ]


def pulse_lifecycle(pulse):
    return compact_mapping(
        {
            "pulse_id": pulse.get("id"),
            "created": pulse.get("created"),
            "modified": pulse.get("modified") or pulse.get("updated"),
            "revision": pulse.get("revision"),
            "public": pulse.get("public"),
            "tlp": (normalize_tlp(pulse) or [""])[0],
        }
    )


def pulse_vote_summary(pulse):
    return compact_mapping(
        {
            "upvotes": first_present(
                pulse,
                "upvotes",
                "upvotes_count",
                "positive_votes",
                "positive_votes_count",
            ),
            "downvotes": first_present(
                pulse,
                "downvotes",
                "downvotes_count",
                "negative_votes",
                "negative_votes_count",
            ),
            "votes": first_present(pulse, "votes", "vote_count"),
            "subscriber_count": first_present(
                pulse,
                "subscriber_count",
                "subscribers_count",
            ),
            "comment_count": first_present(pulse, "comment_count", "comments_count"),
        }
    )


def indicator_observation_window(indicators):
    first_seen = []
    last_seen = []
    for indicator in indicators or []:
        if not isinstance(indicator, dict):
            continue
        first = normalize_value(indicator.get("first_seen"))
        last = normalize_value(indicator.get("last_seen"))
        if first:
            first_seen.append(first)
        if last:
            last_seen.append(last)
    if not first_seen and not last_seen:
        return {}
    return compact_mapping(
        {
            "first_seen_min": min(first_seen) if first_seen else "",
            "last_seen_max": max(last_seen) if last_seen else "",
            "indicator_count_with_first_seen": len(first_seen),
            "indicator_count_with_last_seen": len(last_seen),
        }
    )


def otx_detection_rules(pulse):
    rules = []
    for indicator in flatten(pulse.get("indicators")):
        if not isinstance(indicator, dict):
            continue
        rule_type = normalize_value(indicator.get("type")).lower()
        if rule_type not in DETECTION_RULE_TYPES:
            continue
        pattern = normalize_rule_pattern(
            indicator.get("indicator")
            or indicator.get("value")
            or indicator.get("content")
        )
        if not pattern:
            continue
        title = normalize_value(
            indicator.get("title")
            or indicator.get("description")
            or indicator.get("id")
            or f"{rule_type} detection rule"
        )
        rules.append(
            compact_mapping(
                {
                    "value": title,
                    "rule_type": rule_type,
                    "pattern_type": rule_type,
                    "pattern": pattern,
                    "indicator_type": indicator.get("type"),
                    "indicator_id": indicator.get("id"),
                    "created": indicator.get("created") or indicator.get("created_at"),
                    "first_seen": indicator.get("first_seen"),
                    "last_seen": indicator.get("last_seen"),
                    "source_field": "indicators",
                }
            )
        )
    return deduplicate_detection_rules(rules)


def otx_observables(pulse):
    observables = []
    for indicator in flatten(pulse.get("indicators")):
        if not isinstance(indicator, dict):
            continue
        indicator_type = normalize_value(indicator.get("type"))
        normalized_type = indicator_type.lower()
        observable_type = OBSERVABLE_TYPE_MAP.get(normalized_type)
        value = normalize_value(
            indicator.get("indicator")
            or indicator.get("value")
            or indicator.get("content")
        )
        if not observable_type or not value:
            continue
        observables.append(
            compact_mapping(
                {
                    "value": value,
                    "observable_type": observable_type,
                    "indicator_type": indicator_type,
                    "indicator_id": indicator.get("id"),
                    "hash_algorithm": FILE_HASH_ALGORITHMS.get(normalized_type),
                    "created": indicator.get("created") or indicator.get("created_at"),
                    "first_seen": indicator.get("first_seen"),
                    "last_seen": indicator.get("last_seen"),
                    "source_field": "indicators",
                }
            )
        )
    return deduplicate_observables(observables)


def deduplicate_observables(observables):
    seen = set()
    deduplicated = []
    for observable in observables:
        key = (
            str(observable.get("observable_type", "")).casefold(),
            str(observable.get("hash_algorithm", "")).casefold(),
            str(observable.get("value", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(observable)
    return deduplicated


def deduplicate_detection_rules(rules):
    seen = set()
    deduplicated = []
    for rule in rules:
        key = (
            str(rule.get("indicator_id", "")).casefold(),
            str(rule.get("rule_type", "")).casefold(),
            str(rule.get("pattern", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(rule)
    return deduplicated


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
            record = {
                "entity_type": entity_type,
                "value": value,
                "source_field": source_field,
                "confidence": confidence,
            }
            if entity_type == "source_identity":
                record["attributes"] = {"role": "otx-author"}
            records.append(record)
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
    for observable in entities.get("observables") or []:
        records.append(
            {
                "entity_type": "observable",
                "value": observable.get("value"),
                "source_field": observable.get("source_field") or "indicators",
                "confidence": 65,
                "attributes": {
                    "observable_type": observable.get("observable_type"),
                    "indicator_type": observable.get("indicator_type"),
                    "indicator_id": observable.get("indicator_id"),
                    "hash_algorithm": observable.get("hash_algorithm"),
                    "created": observable.get("created"),
                    "first_seen": observable.get("first_seen"),
                    "last_seen": observable.get("last_seen"),
                },
            }
        )
    for rule in entities.get("detection_rules") or []:
        records.append(
            {
                "entity_type": "detection_rule",
                "value": rule.get("value"),
                "source_field": rule.get("source_field") or "indicators",
                "confidence": 70,
                "attributes": {
                    "rule_type": rule.get("rule_type"),
                    "pattern_type": rule.get("pattern_type"),
                    "pattern": rule.get("pattern"),
                    "indicator_type": rule.get("indicator_type"),
                    "indicator_id": rule.get("indicator_id"),
                    "created": rule.get("created"),
                    "first_seen": rule.get("first_seen"),
                    "last_seen": rule.get("last_seen"),
                },
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


def flatten_text(value):
    if value is None:
        return []
    if isinstance(value, dict):
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


def normalize_value(value):
    if isinstance(value, dict):
        value = (
            value.get("name")
            or value.get("display_name")
            or value.get("value")
            or value.get("id")
            or value.get("url")
            or value.get("title")
        )
    normalized = str(value or "").strip()
    return " ".join(normalized.split())


def normalize_rule_pattern(value):
    return str(value or "").strip()


def first_present(mapping, *keys):
    for key in keys:
        if key in mapping and mapping.get(key) not in ("", None, [], {}):
            return mapping.get(key)
    return ""


def compact_mapping(mapping):
    return {
        key: value
        for key, value in mapping.items()
        if value not in ("", None, [], {})
    }


def domain_from_url(value):
    parsed = urlparse(value or "")
    return parsed.netloc or ""
