import ipaddress
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
    "cidr": "ipv4-addr",
    "ipv4-cidr": "ipv4-addr",
    "ipv6-cidr": "ipv6-addr",
    "netblock": "ipv4-addr",
    "network": "ipv4-addr",
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
    ("adversaries", "adversary", "intrusion_set", 60),
    ("infrastructures", "infrastructures", "infrastructure", 65),
    ("channels", "channels", "channel", 60),
    ("c2_channels", "c2_channels", "channel", 65),
    ("communication_channels", "communication_channels", "channel", 60),
    ("delivery_channels", "delivery_channels", "channel", 60),
    ("marketplaces", "marketplaces", "channel", 60),
    ("malware_families", "malware_families", "malware", 55),
    ("narratives", "narratives", "narrative", 55),
    ("objectives", "objectives", "narrative", 62),
    ("motivations", "motivations", "narrative", 60),
    ("events", "events", "event", 55),
    ("incidents", "incidents", "event", 62),
    ("security_platforms", "security_platforms", "security_platform", 62),
    ("siems", "siems", "security_platform", 65),
    ("edrs", "edrs", "security_platform", 65),
    ("ndrs", "ndrs", "security_platform", 65),
    ("xdrs", "xdrs", "security_platform", 65),
    ("scanners", "scanners", "security_platform", 60),
    ("attack_ids", "attack_ids", "attack_pattern", 70),
    ("vulnerabilities", "vulnerabilities", "vulnerability", 75),
    ("industries", "industries", "target_sector", 50),
    ("targeted_countries", "targeted_countries", "target_country", 50),
    ("targeted_systems", "targeted_systems", "target_system", 60),
    ("tags", "tags", "tag", 35),
)
ACTOR_ANCHORED_ENTITY_TYPES = {
    "attack_pattern",
    "channel",
    "event",
    "infrastructure",
    "malware",
    "narrative",
    "security_platform",
    "target_country",
    "target_sector",
    "target_system",
}
ENTITY_ATTRIBUTE_HINTS_BY_KEY = {
    "c2_channels": {"channel_types": ["c2"]},
    "communication_channels": {"channel_types": ["communication"]},
    "delivery_channels": {"channel_types": ["delivery"]},
    "marketplaces": {"channel_types": ["marketplace"]},
    "objectives": {"narrative_types": ["objective"]},
    "motivations": {"narrative_types": ["motivation"]},
    "incidents": {"event_types": ["incident"]},
    "siems": {"security_platform_type": "SIEM"},
    "edrs": {"security_platform_type": "EDR"},
    "ndrs": {"security_platform_type": "NDR"},
    "xdrs": {"security_platform_type": "XDR"},
    "scanners": {"security_platform_type": "Scanner"},
}
ASN_INDICATOR_TYPES = {
    "as",
    "asn",
    "autonomous-system",
    "autonomous_system",
}
NETWORK_INFRASTRUCTURE_OBSERVABLE_TYPES = {
    "domain-name",
    "ipv4-addr",
    "ipv6-addr",
    "url",
}


def extract_otx_entities(pulse):
    pulse = pulse or {}
    adversaries = normalize_values(pulse.get("adversary"))
    entities = {
        "adversaries": adversaries,
        "malware_families": exclude_conflicting_entity_values(
            normalize_values(pulse.get("malware_families")),
            adversaries,
        ),
        "channels": normalize_safe_graph_values(pulse.get("channels")),
        "c2_channels": normalize_safe_graph_values(
            first_present(
                pulse,
                "c2_channels",
                "c2_channel",
                "command_and_control_channels",
                "command_and_control_channel",
            )
        ),
        "communication_channels": normalize_safe_graph_values(
            first_present(pulse, "communication_channels", "communication_channel")
        ),
        "delivery_channels": normalize_safe_graph_values(
            first_present(pulse, "delivery_channels", "delivery_channel")
        ),
        "marketplaces": normalize_safe_graph_values(
            first_present(pulse, "marketplaces", "marketplace")
        ),
        "narratives": normalize_safe_graph_values(pulse.get("narratives")),
        "objectives": normalize_safe_graph_values(
            first_present(pulse, "objectives", "objective", "goals", "goal")
        ),
        "motivations": normalize_safe_graph_values(
            first_present(pulse, "motivations", "motivation")
        ),
        "events": normalize_safe_graph_values(
            first_present(pulse, "events", "event_names", "event_name")
        ),
        "incidents": normalize_safe_graph_values(
            first_present(pulse, "incidents", "incident_names", "incident_name")
        ),
        "security_platforms": normalize_safe_graph_values(
            first_present(
                pulse,
                "security_platforms",
                "security_platform",
                "detection_platforms",
                "detection_platform",
            )
        ),
        "siems": normalize_safe_graph_values(first_present(pulse, "siems", "siem")),
        "edrs": normalize_safe_graph_values(first_present(pulse, "edrs", "edr")),
        "ndrs": normalize_safe_graph_values(first_present(pulse, "ndrs", "ndr")),
        "xdrs": normalize_safe_graph_values(first_present(pulse, "xdrs", "xdr")),
        "scanners": normalize_safe_graph_values(
            first_present(pulse, "scanners", "scanner")
        ),
        "attack_ids": normalize_attack_ids(pulse.get("attack_ids")),
        "vulnerabilities": normalize_cve_ids(cve_sources(pulse)),
        "industries": normalize_values(pulse.get("industries")),
        "targeted_countries": normalize_values(
            pulse.get("targeted_countries") or pulse.get("target_countries")
        ),
        "targeted_systems": normalize_safe_graph_values(
            first_present(
                pulse,
                "targeted_systems",
                "targeted_system",
                "target_systems",
                "target_system",
                "affected_systems",
                "affected_system",
                "targeted_platforms",
                "targeted_platform",
                "affected_platforms",
                "affected_platform",
                "operating_systems",
                "operating_system",
            )
        ),
        "authors": normalize_authors(author_sources(pulse)),
        "lifecycle": pulse_lifecycle(pulse),
        "vote_summary": pulse_vote_summary(pulse),
        "indicator_observation_window": indicator_observation_window(
            pulse.get("indicators")
        ),
        "observables": otx_observables(pulse),
        "autonomous_systems": otx_autonomous_systems(pulse),
        "detection_rules": otx_detection_rules(pulse),
        "tlp": normalize_tlp(pulse),
        "references": normalize_references(pulse.get("references")),
        "tags": normalize_values(pulse.get("tags")),
    }
    entities["infrastructures"] = inferred_network_infrastructures(entities)
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


def normalize_safe_graph_values(value):
    values = []
    for item in normalize_values(value):
        if is_safe_graph_context_value(item):
            values.append(item)
    return values


def is_safe_graph_context_value(value):
    value = normalize_value(value)
    lowered = value.casefold()
    if not value:
        return False
    if lowered in {
        "alienvault",
        "alienvault otx",
        "misp",
        "narrowcti",
        "narrowcti gateway",
        "opencti",
        "otx",
        "the mitre corporation",
    }:
        return False
    if lowered.startswith(("http://", "https://", "ftp://", "tlp:")):
        return False
    if "@" in value and not any(char.isspace() for char in value):
        return False
    if ATTACK_ID_PATTERN.fullmatch(value) or CVE_ID_PATTERN.fullmatch(value):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    if re.fullmatch(r"\d+", value):
        return False
    return True


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


def exclude_conflicting_entity_values(values, conflicting_values):
    conflicts = {semantic_value_key(value) for value in conflicting_values}
    return [
        value
        for value in values
        if semantic_value_key(value) and semantic_value_key(value) not in conflicts
    ]


def semantic_value_key(value):
    return re.sub(r"[^a-z0-9]+", "", normalize_value(value).casefold())


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
        value, observable_type = normalize_observable_value(value, observable_type)
        if not value:
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


def normalize_observable_value(value, observable_type):
    value = normalize_value(value)
    observable_type = normalize_value(observable_type)
    if observable_type not in {"ipv4-addr", "ipv6-addr"}:
        return value, observable_type
    parsed = parse_ip_or_network(value)
    if not parsed:
        return value, observable_type
    return parsed["value"], parsed["observable_type"]


def parse_ip_or_network(value):
    value = normalize_value(value)
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            observable_type = "ipv4-addr" if network.version == 4 else "ipv6-addr"
            return {"value": str(network), "observable_type": observable_type}
        address = ipaddress.ip_address(value)
        observable_type = "ipv4-addr" if address.version == 4 else "ipv6-addr"
        return {"value": str(address), "observable_type": observable_type}
    except ValueError:
        return {}


def otx_autonomous_systems(pulse):
    autonomous_systems = []
    for indicator in flatten(pulse.get("indicators")):
        if not isinstance(indicator, dict):
            continue
        indicator_type = normalize_value(indicator.get("type"))
        normalized_type = indicator_type.lower()
        value = normalize_value(
            indicator.get("indicator")
            or indicator.get("value")
            or indicator.get("content")
        )
        if normalized_type not in ASN_INDICATOR_TYPES and not value.upper().startswith(
            "AS"
        ):
            continue
        asn_number = parse_asn_number(value)
        if asn_number is None:
            continue
        as_name = normalize_value(
            indicator.get("as_name")
            or indicator.get("asn_name")
            or indicator.get("name")
            or indicator.get("title")
            or indicator.get("description")
        )
        autonomous_systems.append(
            compact_mapping(
                {
                    "value": autonomous_system_value(asn_number, as_name),
                    "number": asn_number,
                    "as_name": as_name,
                    "indicator_type": indicator_type,
                    "indicator_id": indicator.get("id"),
                    "created": indicator.get("created") or indicator.get("created_at"),
                    "first_seen": indicator.get("first_seen"),
                    "last_seen": indicator.get("last_seen"),
                    "source_field": "indicators",
                }
            )
        )
    return deduplicate_autonomous_systems(autonomous_systems)


def parse_asn_number(value):
    text = normalize_value(value)
    if not text:
        return None
    match = re.search(r"\bAS\s*([0-9]{1,10})\b", text, re.IGNORECASE)
    if not match and text.isdigit():
        match = re.match(r"^([0-9]{1,10})$", text)
    if not match:
        return None
    number = int(match.group(1))
    if number < 0 or number > 4294967295:
        return None
    return number


def autonomous_system_value(number, name=""):
    name = normalize_value(name)
    if name and semantic_value_key(name) != f"as{number}":
        return f"AS{number} {name}"
    return f"AS{number}"


def deduplicate_autonomous_systems(autonomous_systems):
    best_by_number = {}
    for autonomous_system in autonomous_systems:
        key = autonomous_system.get("number")
        current = best_by_number.get(key)
        if not current or len(autonomous_system.get("value", "")) > len(
            current.get("value", "")
        ):
            best_by_number[key] = autonomous_system
    return list(best_by_number.values())


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
    infrastructure_value = first_inferred_infrastructure(entities)
    for key, source_field, entity_type, confidence in ENTITY_SPECS:
        for value in entities.get(key) or []:
            attributes = entity_specific_attributes(key)
            attributes.update(relationship_anchor_attributes(entities, entity_type))
            record = {
                "entity_type": entity_type,
                "value": value,
                "source_field": source_field,
                "confidence": confidence,
            }
            if attributes:
                record["attributes"] = attributes
            records.append(record)
    records.extend(infrastructure_attack_pattern_records(entities, infrastructure_value))
    records.extend(autonomous_system_records(entities, infrastructure_value))
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
        attributes = {
            "observable_type": observable.get("observable_type"),
            "indicator_type": observable.get("indicator_type"),
            "indicator_id": observable.get("indicator_id"),
            "hash_algorithm": observable.get("hash_algorithm"),
            "created": observable.get("created"),
            "first_seen": observable.get("first_seen"),
            "last_seen": observable.get("last_seen"),
        }
        record = {
            "entity_type": "observable",
            "value": observable.get("value"),
            "source_field": observable.get("source_field") or "indicators",
            "confidence": 65,
            "attributes": attributes,
        }
        if infrastructure_value and is_network_infrastructure_observable(observable):
            record["relationship_type"] = "consists-of"
            attributes.update(
                {
                    "relationship_source_stix_object_type": "infrastructure",
                    "relationship_source_value": infrastructure_value,
                    "relationship_source_field": "infrastructures",
                    "relationship_inference": (
                        "otx-single-adversary-network-observable"
                    ),
                }
            )
        records.append(record)
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


def entity_specific_attributes(key):
    return dict(ENTITY_ATTRIBUTE_HINTS_BY_KEY.get(key, {}))


def relationship_anchor_attributes(entities, entity_type):
    if entity_type not in ACTOR_ANCHORED_ENTITY_TYPES:
        return {}
    adversaries = entities.get("adversaries") or []
    if len(adversaries) != 1:
        return {}
    return {
        "relationship_source_stix_object_type": "intrusion-set",
        "relationship_source_value": adversaries[0],
        "relationship_source_field": "adversary",
    }


def infrastructure_attack_pattern_records(entities, infrastructure_value):
    if not infrastructure_value:
        return []
    records = []
    for attack_id in entities.get("attack_ids") or []:
        records.append(
            {
                "entity_type": "attack_pattern",
                "value": attack_id,
                "source_field": "attack_ids",
                "confidence": 70,
                "relationship_type": "related-to",
                "attributes": {
                    "relationship_source_stix_object_type": "infrastructure",
                    "relationship_source_value": infrastructure_value,
                    "relationship_source_field": "infrastructures",
                    "relationship_inference": (
                        "otx-single-adversary-infrastructure-ttp"
                    ),
                },
            }
        )
    return records


def autonomous_system_records(entities, infrastructure_value):
    records = []
    for autonomous_system in entities.get("autonomous_systems") or []:
        attributes = {
            "asn": autonomous_system.get("number"),
            "asn_name": autonomous_system.get("as_name"),
            "indicator_type": autonomous_system.get("indicator_type"),
            "indicator_id": autonomous_system.get("indicator_id"),
            "created": autonomous_system.get("created"),
            "first_seen": autonomous_system.get("first_seen"),
            "last_seen": autonomous_system.get("last_seen"),
        }
        relationship_type = "related-to"
        if infrastructure_value:
            relationship_type = "consists-of"
            attributes.update(
                {
                    "relationship_source_stix_object_type": "infrastructure",
                    "relationship_source_value": infrastructure_value,
                    "relationship_source_field": "infrastructures",
                    "relationship_inference": "otx-single-adversary-asn",
                }
            )
        records.append(
            {
                "entity_type": "autonomous_system",
                "value": autonomous_system.get("value"),
                "source_field": autonomous_system.get("source_field") or "indicators",
                "confidence": 70,
                "relationship_type": relationship_type,
                "attributes": compact_mapping(attributes),
            }
        )
    return records


def inferred_network_infrastructures(entities):
    adversaries = entities.get("adversaries") or []
    if len(adversaries) != 1:
        return []
    has_network_observable = any(
        is_network_infrastructure_observable(observable)
        for observable in entities.get("observables") or []
    )
    if not has_network_observable and not entities.get("autonomous_systems"):
        return []
    pulse_id = normalize_value((entities.get("lifecycle") or {}).get("pulse_id"))
    suffix = f" {pulse_id[:8]}" if pulse_id else ""
    return [f"{adversaries[0]} OTX observed infrastructure{suffix}"]


def first_inferred_infrastructure(entities):
    infrastructures = entities.get("infrastructures") or []
    return infrastructures[0] if len(infrastructures) == 1 else ""


def is_network_infrastructure_observable(observable):
    return (
        normalize_value(observable.get("observable_type")).lower()
        in NETWORK_INFRASTRUCTURE_OBSERVABLE_TYPES
    )


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
