from __future__ import annotations

import ipaddress
import re

from ._common import clean_text, compact_mapping, is_truthy, list_values



MISP_INFRASTRUCTURE_OBJECT_NAMES = {
    "asn",
    "domain-ip",
    "ip-port",
    "netblock",
}

MISP_INFRASTRUCTURE_ATTRIBUTE_OBJECT_NAMES = {
    "as": "asn",
    "asn": "asn",
    "domain|ip": "domain-ip",
    "hostname|port": "ip-port",
    "ip-dst|port": "ip-port",
    "ip-src|port": "ip-port",
}



def extract_misp_infrastructure(event, ip_asn_enricher=None):
    event = compact_mapping(event)
    records = []
    for attribute_index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        records.extend(
            normalize_misp_infrastructure_attribute(
                attribute,
                f"Attribute[{attribute_index}]",
                ip_asn_enricher=ip_asn_enricher,
            )
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        records.extend(
            normalize_misp_infrastructure_object(
                misp_object,
                f"Object[{object_index}]",
                ip_asn_enricher=ip_asn_enricher,
            )
        )
    return deduplicate_misp_infrastructure_records(
        canonicalize_misp_autonomous_system_values(records)
    )

def normalize_misp_infrastructure_attribute(
    attribute,
    source_field,
    ip_asn_enricher=None,
):
    attribute = compact_mapping(attribute)
    if not attribute or is_truthy(attribute.get("deleted")):
        return []
    attribute_type = clean_text(attribute.get("type")).casefold()
    object_name = MISP_INFRASTRUCTURE_ATTRIBUTE_OBJECT_NAMES.get(attribute_type)
    if not object_name:
        return []
    pseudo_object = {
        "uuid": attribute.get("uuid"),
        "name": object_name,
        "meta-category": attribute.get("category") or "network",
        "Attribute": [attribute],
    }
    return normalize_misp_infrastructure_object(
        pseudo_object,
        source_field,
        ip_asn_enricher=ip_asn_enricher,
    )

def normalize_misp_infrastructure_object(
    misp_object,
    source_field,
    ip_asn_enricher=None,
):
    misp_object = compact_mapping(misp_object)
    object_name = clean_text(misp_object.get("name")).casefold()
    if object_name not in MISP_INFRASTRUCTURE_OBJECT_NAMES:
        return []

    attributes = misp_object_attribute_facts(misp_object, source_field)
    observables = infrastructure_observables(attributes)
    asn = infrastructure_asn(attributes)
    if not observables and not asn:
        return []

    records = []
    infrastructure_name = ""
    if object_name != "asn" and observables:
        infrastructure_name = misp_infrastructure_name(
            object_name,
            observables,
            asn,
            misp_object,
        )
        records.append(
            misp_infrastructure_record(
                "infrastructure",
                infrastructure_name,
                "infrastructure",
                "uses",
                source_field,
                misp_object,
                confidence=72,
            )
        )

    for observable in observables:
        observable_attributes = misp_infrastructure_record_attributes(
            misp_object,
            observable["source_field"],
        )
        observable_attributes.update(
            {
                "observable_type": observable["observable_type"],
                "attribute_type": observable.get("attribute_type"),
                "attribute_relation": observable.get("relation"),
                "attribute_uuid": observable.get("attribute_uuid"),
                "first_seen": observable.get("first_seen"),
                "last_seen": observable.get("last_seen"),
                "port": observable.get("port"),
            }
        )
        if infrastructure_name:
            observable_attributes.update(
                relationship_source_attributes(
                    "infrastructure",
                    infrastructure_name,
                    observable["source_field"],
                )
            )
        records.append(
            misp_infrastructure_record(
                "observable",
                observable["value"],
                "observable",
                "consists-of" if infrastructure_name else "related-to",
                observable["source_field"],
                misp_object,
                confidence=70,
                attributes=observable_attributes,
            )
        )

    if asn:
        asn_attributes = misp_infrastructure_record_attributes(
            misp_object,
            asn["source_field"],
        )
        asn_attributes.update(
            {
                "asn": asn["number"],
                "asn_name": asn.get("name"),
                "rir": asn.get("rir"),
                "attribute_type": asn.get("attribute_type"),
                "attribute_relation": asn.get("relation"),
                "attribute_uuid": asn.get("attribute_uuid"),
                "first_seen": asn.get("first_seen"),
                "last_seen": asn.get("last_seen"),
            }
        )
        if infrastructure_name:
            infra_asn_attributes = dict(asn_attributes)
            infra_asn_attributes.update(
                relationship_source_attributes(
                    "infrastructure",
                    infrastructure_name,
                    asn["source_field"],
                )
            )
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    autonomous_system_value(asn),
                    "autonomous-system",
                    "consists-of",
                    asn["source_field"],
                    misp_object,
                    confidence=72,
                    attributes=infra_asn_attributes,
                )
            )
        else:
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    autonomous_system_value(asn),
                    "autonomous-system",
                    "related-to",
                    asn["source_field"],
                    misp_object,
                    confidence=72,
                    attributes=asn_attributes,
                )
            )
        for observable in observables:
            if observable["observable_type"] not in {"ipv4-addr", "ipv6-addr"}:
                continue
            belongs_attributes = dict(asn_attributes)
            belongs_attributes.update(
                relationship_source_attributes(
                    "observable",
                    observable["value"],
                    observable["source_field"],
                )
            )
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    autonomous_system_value(asn),
                    "autonomous-system",
                    "belongs-to",
                    asn["source_field"],
                    misp_object,
                    confidence=72,
                    attributes=belongs_attributes,
                )
            )
    records.extend(
        offline_ip_asn_records(
            observables,
            ip_asn_enricher,
            source_field,
            misp_object,
            infrastructure_name,
        )
    )
    return records

def offline_ip_asn_records(
    observables,
    ip_asn_enricher,
    source_field,
    misp_object,
    infrastructure_name="",
):
    if not ip_asn_enricher:
        return []
    records = []
    for observable in observables:
        if observable.get("observable_type") not in {"ipv4-addr", "ipv6-addr"}:
            continue
        match = ip_asn_enricher.lookup(observable.get("value"))
        if not match:
            continue
        attributes = misp_infrastructure_record_attributes(
            misp_object,
            observable.get("source_field") or source_field,
        )
        attributes.update(
            {
                "asn": match.asn,
                "asn_name": match.as_name,
                "rir": match.rir,
                "enrichment_source": match.source or "offline-ip-asn",
                "enrichment_cidr": str(match.network),
            }
        )
        attributes.update(
            relationship_source_attributes(
                "observable",
                observable["value"],
                observable.get("source_field") or source_field,
            )
        )
        records.append(
            misp_infrastructure_record(
                "autonomous_system",
                match.value,
                "autonomous-system",
                "belongs-to",
                observable.get("source_field") or source_field,
                misp_object,
                confidence=60,
                attributes=attributes,
            )
        )
        if infrastructure_name:
            infra_attributes = dict(attributes)
            infra_attributes.update(
                relationship_source_attributes(
                    "infrastructure",
                    infrastructure_name,
                    observable.get("source_field") or source_field,
                )
            )
            records.append(
                misp_infrastructure_record(
                    "autonomous_system",
                    match.value,
                    "autonomous-system",
                    "consists-of",
                    observable.get("source_field") or source_field,
                    misp_object,
                    confidence=60,
                    attributes=infra_attributes,
                )
            )
    return records

def misp_object_attribute_facts(misp_object, object_source_field):
    facts = []
    for attribute_index, attribute in enumerate(
        list_values(compact_mapping(misp_object).get("Attribute"))
    ):
        attribute = compact_mapping(attribute)
        if not attribute or is_truthy(attribute.get("deleted")):
            continue
        if object_source_field.startswith("Attribute[") and attribute_index == 0:
            source_field = object_source_field
        else:
            source_field = f"{object_source_field}.Attribute[{attribute_index}]"
        relation = clean_text(
            attribute.get("object_relation")
            or attribute.get("relation")
            or attribute.get("type")
        ).casefold()
        attribute_type = clean_text(attribute.get("type")).casefold()
        value = clean_text(attribute.get("value"))
        if not value:
            continue
        facts.append(
            {
                "relation": relation,
                "attribute_type": attribute_type,
                "value": value,
                "uuid": attribute.get("uuid"),
                "comment": attribute.get("comment"),
                "first_seen": attribute.get("first_seen"),
                "last_seen": attribute.get("last_seen"),
                "source_field": source_field,
            }
        )
    return facts

def infrastructure_observables(attributes):
    observables = []
    for fact in attributes:
        relation = fact["relation"]
        attribute_type = fact["attribute_type"]
        value = fact["value"]
        values = infrastructure_observable_values(attribute_type, relation, value)
        for observable in values:
            observable["relation"] = relation
            observable["attribute_type"] = attribute_type
            observable["attribute_uuid"] = fact.get("uuid")
            observable["first_seen"] = fact.get("first_seen")
            observable["last_seen"] = fact.get("last_seen")
            observable["source_field"] = fact["source_field"]
            observables.append(observable)
    return deduplicate_observables(observables)

def infrastructure_observable_values(attribute_type, relation, value):
    values = []
    parts = [part.strip() for part in value.split("|") if part.strip()]
    relation_type = f"{attribute_type}|{relation}"
    if len(parts) >= 2 and (
        "domain|ip" in relation_type
        or "hostname|port" in relation_type
        or "ip-src|port" in relation_type
        or "ip-dst|port" in relation_type
    ):
        if "domain|ip" in relation_type:
            values.extend(observable_values_from_text(parts[0], preferred="domain-name"))
            values.extend(observable_values_from_text(parts[1], preferred="ip"))
            return values
        if "hostname|port" in relation_type:
            values.extend(observable_values_from_text(parts[0], preferred="domain-name"))
            attach_port(values, parts[1])
            return values
        values.extend(observable_values_from_text(parts[0], preferred="ip"))
        attach_port(values, parts[1])
        return values

    preferred = ""
    if relation in {"domain", "hostname", "host", "fqdn"} or attribute_type in {
        "domain",
        "hostname",
    }:
        preferred = "domain-name"
    elif relation in {"url"} or attribute_type == "url":
        preferred = "url"
    elif relation in {
        "cidr",
        "netblock",
        "subnet",
        "subnet-announced",
        "ip-subnet",
    }:
        preferred = "ip-network"
    elif relation in {
        "ip",
        "ip-src",
        "ip-dst",
        "src-ip",
        "dst-ip",
        "first-ip",
        "last-ip",
    } or attribute_type in {"ip-src", "ip-dst"}:
        preferred = "ip"
    return observable_values_from_text(value, preferred=preferred)

def observable_values_from_text(value, preferred=""):
    value = clean_text(value)
    if not value:
        return []
    if preferred in {"ip", "ip-network"} or "/" in value:
        parsed = parse_ip_observable(value)
        if parsed:
            return [parsed]
        if preferred in {"ip", "ip-network"}:
            return []
    if preferred == "url" or value.lower().startswith(("http://", "https://")):
        return [{"value": value, "observable_type": "url"}]
    if preferred == "domain-name" or is_domain_value(value):
        return [{"value": value.lower(), "observable_type": "domain-name"}]
    parsed = parse_ip_observable(value)
    if parsed:
        return [parsed]
    return []

def parse_ip_observable(value):
    value = clean_text(value)
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

def is_domain_value(value):
    value = clean_text(value).lower()
    if not value or " " in value or "/" in value or ":" in value:
        return False
    if "." not in value:
        return False
    return bool(re.match(r"^[a-z0-9_.-]+$", value))

def attach_port(observables, port):
    port = clean_text(port)
    if not port:
        return
    for observable in observables:
        observable["port"] = port

def deduplicate_observables(observables):
    seen = set()
    deduplicated = []
    for observable in observables:
        key = (
            observable.get("observable_type", ""),
            observable.get("value", "").casefold(),
            observable.get("port", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(observable)
    return deduplicated

def infrastructure_asn(attributes):
    number = None
    asn_fact = {}
    as_name = ""
    rir = ""
    for fact in attributes:
        relation = fact["relation"]
        attribute_type = fact["attribute_type"]
        value = fact["value"]
        asn_field = relation in {
            "asn",
            "as",
            "number",
            "autonomous-system",
        } or attribute_type in {"as", "asn"}
        asn_literal = re.search(r"\bAS\s*[0-9]{1,10}\b", value, re.IGNORECASE)
        if number is None and (asn_field or asn_literal):
            parsed = parse_asn_number(value)
            if parsed is not None:
                number = parsed
                asn_fact = fact
                continue
        if relation in {
            "as-name",
            "asn-name",
            "description",
            "name",
            "org",
            "organization",
            "organisation",
        }:
            as_name = as_name or value
        if relation in {"rir", "registry"}:
            rir = rir or value
    if number is None:
        return {}
    return {
        "number": number,
        "name": as_name,
        "rir": rir,
        "relation": asn_fact.get("relation"),
        "attribute_type": asn_fact.get("attribute_type"),
        "attribute_uuid": asn_fact.get("uuid"),
        "first_seen": asn_fact.get("first_seen"),
        "last_seen": asn_fact.get("last_seen"),
        "source_field": asn_fact.get("source_field", "Attribute"),
    }

def parse_asn_number(value):
    text = clean_text(value)
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

def autonomous_system_value(asn):
    number = asn.get("number")
    name = clean_text(asn.get("name"))
    if name and name.casefold() != f"as{number}":
        return f"AS{number} {name}"
    return f"AS{number}"

def misp_infrastructure_name(object_name, observables, asn, misp_object):
    preferred = ""
    for observable in observables:
        if observable["observable_type"] in {"domain-name", "url"}:
            preferred = observable["value"]
            break
    if not preferred and observables:
        preferred = observables[0]["value"]
    if not preferred and asn:
        preferred = autonomous_system_value(asn)
    if not preferred:
        preferred = clean_text(misp_object.get("uuid")) or object_name
    return f"MISP {object_name} {preferred}"

def misp_infrastructure_record(
    entity_type,
    value,
    stix_object_type,
    relationship_type,
    source_field,
    misp_object,
    confidence=70,
    attributes=None,
):
    return compact_mapping(
        {
            "entity_type": entity_type,
            "value": value,
            "stix_object_type": stix_object_type,
            "relationship_type": relationship_type,
            "source_field": source_field,
            "confidence": confidence,
            "attributes": compact_mapping(attributes)
            or misp_infrastructure_record_attributes(misp_object, source_field),
        }
    )

def misp_infrastructure_record_attributes(misp_object, source_field):
    return compact_mapping(
        {
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "object_meta_category": misp_object.get("meta-category"),
            "source_field": source_field,
        }
    )

def relationship_source_attributes(stix_object_type, value, source_field):
    return {
        "relationship_source_stix_object_type": stix_object_type,
        "relationship_source_value": value,
        "relationship_source_field": source_field,
    }

def deduplicate_misp_infrastructure_records(records):
    seen = set()
    deduplicated = []
    for record in records:
        attributes = compact_mapping(record.get("attributes"))
        key = (
            str(record.get("entity_type", "")).casefold(),
            str(record.get("value", "")).casefold(),
            str(record.get("relationship_type", "")).casefold(),
            str(attributes.get("relationship_source_stix_object_type", "")).casefold(),
            str(attributes.get("relationship_source_value", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(record)
    return deduplicated

def canonicalize_misp_autonomous_system_values(records):
    canonical_by_asn = {}
    for record in records:
        if record.get("entity_type") != "autonomous_system":
            continue
        attributes = compact_mapping(record.get("attributes"))
        asn = attributes.get("asn")
        if asn in ("", None):
            continue
        value = clean_text(record.get("value"))
        current = canonical_by_asn.get(asn, "")
        if len(value) > len(current):
            canonical_by_asn[asn] = value

    canonicalized = []
    for record in records:
        if record.get("entity_type") != "autonomous_system":
            canonicalized.append(record)
            continue
        attributes = compact_mapping(record.get("attributes"))
        asn = attributes.get("asn")
        canonical = canonical_by_asn.get(asn)
        if not canonical:
            canonicalized.append(record)
            continue
        updated = dict(record)
        updated["value"] = canonical
        canonicalized.append(updated)
    return canonicalized
