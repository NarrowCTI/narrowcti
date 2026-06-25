from collections import Counter
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from stix2 import (
    AttackPattern,
    Bundle,
    DomainName,
    EmailAddress,
    File,
    IPv4Address,
    IPv6Address,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    Note,
    Relationship,
    Report,
    ThreatActor,
    Tool,
    URL,
    Vulnerability,
)


SEMANTIC_RELATIONSHIP_TYPES = {
    "attributed-to",
    "based-on",
    "detects",
    "indicates",
    "targets",
    "uses",
}
REPORT_ID_NAMESPACE = "https://narrowcti.local/stix/report"
IDENTITY_ID_NAMESPACE = "https://narrowcti.local/stix/identity"


def escape_pattern_value(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def indicator_pattern(raw_indicator):
    value = raw_indicator.get("indicator")
    indicator_type = raw_indicator.get("type", "").lower()

    if not value:
        return None

    escaped = escape_pattern_value(value)
    pattern_by_type = {
        "domain": f"[domain-name:value = '{escaped}']",
        "hostname": f"[domain-name:value = '{escaped}']",
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
        "email": f"[email-addr:value = '{escaped}']",
        "filehash-md5": f"[file:hashes.MD5 = '{escaped}']",
        "filehash-sha1": f"[file:hashes.SHA1 = '{escaped}']",
        "filehash-sha256": f"[file:hashes.SHA256 = '{escaped}']",
    }
    return pattern_by_type.get(indicator_type)


def build_indicators(raw_indicators, identity_id, score, valid_from):
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


def build_report_bundle(
    name,
    description,
    score,
    indicators=None,
    identity_name="NarrowCTI Gateway",
):
    now = datetime.now(timezone.utc)
    identity = build_identity(identity_name)
    indicator_objects = build_indicators(indicators or [], identity.id, score, now)
    object_refs = [indicator.id for indicator in indicator_objects] or [identity.id]

    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        object_refs,
    )

    bundle = Bundle(objects=[identity, *indicator_objects, report], allow_custom=True)
    return bundle, len(indicator_objects)


def build_curated_report_bundle(
    name,
    description,
    score,
    indicators=None,
    graph_candidate_policy=None,
    identity_name="NarrowCTI Gateway",
):
    now = datetime.now(timezone.utc)
    identity = build_identity(identity_name)
    indicator_objects = build_indicators(indicators or [], identity.id, score, now)
    accepted_candidates = graph_accepted_candidates(graph_candidate_policy)
    graph_content = build_graph_content(accepted_candidates, identity.id, now)

    object_refs = [
        *[indicator.id for indicator in indicator_objects],
        *graph_content["object_refs"],
    ] or [identity.id]
    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        object_refs,
    )
    relationship_content = build_graph_relationships(
        accepted_candidates,
        graph_content["object_ids"],
        report.id,
        identity.id,
    )

    bundle = Bundle(
        objects=[
            identity,
            *indicator_objects,
            *graph_content["objects"],
            *relationship_content["relationships"],
            report,
        ],
        allow_custom=True,
    )
    summary = graph_bundle_summary(
        accepted_candidates,
        bundle,
        graph_content,
        relationship_content,
    )
    summary["indicator_count"] = len(indicator_objects)
    return bundle, len(indicator_objects), summary


def build_graph_report_bundle(
    name,
    description,
    score,
    graph_candidate_policy=None,
    identity_name="NarrowCTI Gateway",
):
    now = datetime.now(timezone.utc)
    identity = build_identity(identity_name)
    accepted_candidates = graph_accepted_candidates(graph_candidate_policy)
    graph_content = build_graph_content(accepted_candidates, identity.id, now)

    report_refs = graph_content["object_refs"] or [identity.id]
    report = build_stix_report(
        name,
        description,
        score,
        now,
        identity.id,
        report_refs,
    )
    relationship_content = build_graph_relationships(
        accepted_candidates,
        graph_content["object_ids"],
        report.id,
        identity.id,
    )

    bundle = Bundle(
        objects=[
            identity,
            *graph_content["objects"],
            *relationship_content["relationships"],
            report,
        ],
        allow_custom=True,
    )
    summary = graph_bundle_summary(
        accepted_candidates,
        bundle,
        graph_content,
        relationship_content,
    )
    return bundle, summary


def build_stix_report(name, description, score, now, identity_id, object_refs):
    return Report(
        id=deterministic_report_id(name, description),
        name=name,
        description=description or "",
        report_types=["threat-report"],
        confidence=score,
        created=now,
        modified=now,
        published=now,
        created_by_ref=identity_id,
        object_refs=object_refs,
    )


def build_identity(identity_name, identity_class="organization"):
    return Identity(
        id=deterministic_identity_id(identity_name, identity_class),
        name=identity_name,
        identity_class=identity_class,
    )


def deterministic_identity_id(name, identity_class="organization"):
    material = "|".join(
        (
            IDENTITY_ID_NAMESPACE,
            clean_string(identity_class).casefold() or "organization",
            clean_string(name).casefold() or "unknown",
        )
    )
    return f"identity--{uuid5(NAMESPACE_URL, material)}"


def deterministic_report_id(name, description):
    material = "|".join(
        (
            "narrowcti-report",
            clean_string(name).casefold(),
            clean_string(description).casefold(),
        )
    )
    return f"report--{uuid5(NAMESPACE_URL, material)}"


def build_graph_content(accepted_candidates, identity_id, now):
    graph_objects = []
    graph_object_ids = {}
    skipped_candidates = []
    object_counts = Counter()
    existing_reference_counts = Counter()

    for candidate in accepted_candidates:
        object_key = graph_object_key(candidate)
        if object_key in graph_object_ids:
            continue
        existing_ref = existing_opencti_ref(candidate)
        if existing_ref:
            graph_object_ids[object_key] = existing_ref
            existing_reference_counts[
                clean_string(candidate.get("stix_object_type")).lower()
            ] += 1
            continue
        try:
            stix_object = graph_candidate_to_stix_object(candidate, identity_id, now)
        except Exception:
            stix_object = None
        if not stix_object:
            skipped_candidates.append(candidate_summary(candidate))
            continue
        graph_object_ids[object_key] = stix_object.id
        graph_objects.append(stix_object)
        object_counts[stix_object.type] += 1

    return {
        "objects": graph_objects,
        "object_ids": graph_object_ids,
        "object_refs": list(graph_object_ids.values()),
        "skipped_candidates": skipped_candidates,
        "object_counts": object_counts,
        "existing_reference_counts": existing_reference_counts,
    }


def build_graph_relationships(
    accepted_candidates,
    graph_object_ids,
    report_id,
    identity_id,
):
    graph_relationships = []
    relationship_keys = set()
    relationship_counts = Counter()
    proposed_relationship_counts = Counter()
    semantic_relationship_count = 0
    report_relationship_count = 0
    for candidate in accepted_candidates:
        target_ref = graph_object_ids.get(graph_object_key(candidate))
        if not target_ref:
            continue
        source_ref, relationship_type, relationship_mode = graph_relationship_endpoint(
            candidate,
            graph_object_ids,
            report_id,
            target_ref,
        )
        relationship_key = (source_ref, relationship_type, target_ref)
        if relationship_key in relationship_keys:
            continue
        relationship_keys.add(relationship_key)
        relationship = Relationship(
            source_ref=source_ref,
            relationship_type=relationship_type,
            target_ref=target_ref,
            confidence=clamp_stix_confidence(
                candidate.get("relationship_confidence", candidate.get("confidence"))
            ),
            created_by_ref=identity_id,
            custom_properties=graph_relationship_custom_properties(
                candidate,
                relationship_mode,
            ),
            allow_custom=True,
        )
        graph_relationships.append(relationship)
        relationship_counts[relationship_type] += 1
        proposed_relationship_counts[
            clean_string(candidate.get("relationship_type")) or "related-to"
        ] += 1
        if relationship_mode == "semantic":
            semantic_relationship_count += 1
        else:
            report_relationship_count += 1

    return {
        "relationships": graph_relationships,
        "relationship_counts": relationship_counts,
        "proposed_relationship_counts": proposed_relationship_counts,
        "semantic_relationship_count": semantic_relationship_count,
        "report_relationship_count": report_relationship_count,
    }


def graph_bundle_summary(
    accepted_candidates,
    bundle,
    graph_content,
    relationship_content,
):
    return {
        "accepted_candidate_count": len(accepted_candidates),
        "bundle_object_count": len(bundle.objects),
        "graph_object_count": len(graph_content["objects"]),
        "existing_reference_count": sum(
            graph_content["existing_reference_counts"].values()
        ),
        "graph_relationship_count": len(relationship_content["relationships"]),
        "skipped_candidate_count": len(graph_content["skipped_candidates"]),
        "object_counts": dict(sorted(graph_content["object_counts"].items())),
        "existing_reference_counts": dict(
            sorted(graph_content["existing_reference_counts"].items())
        ),
        "relationship_counts": dict(
            sorted(relationship_content["relationship_counts"].items())
        ),
        "proposed_relationship_counts": dict(
            sorted(relationship_content["proposed_relationship_counts"].items())
        ),
        "semantic_relationship_count": relationship_content[
            "semantic_relationship_count"
        ],
        "report_relationship_count": relationship_content[
            "report_relationship_count"
        ],
        "skipped_candidates": graph_content["skipped_candidates"],
    }


def graph_accepted_candidates(graph_candidate_policy):
    policy = graph_candidate_policy if isinstance(graph_candidate_policy, dict) else {}
    return [
        candidate
        for candidate in policy.get("accepted") or []
        if isinstance(candidate, dict)
    ]


def existing_opencti_ref(candidate):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    existing_ref = clean_string(attributes.get("opencti_existing_ref"))
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    if existing_ref and stix_object_type and existing_ref.startswith(
        f"{stix_object_type}--"
    ):
        return existing_ref
    return ""


def graph_candidate_to_stix_object(candidate, identity_id, now):
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    name = clean_string(candidate.get("name") or candidate.get("value"))
    value = clean_string(candidate.get("value"))
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    confidence = clamp_stix_confidence(candidate.get("confidence"))
    custom_properties = graph_custom_properties(candidate)

    if not name or not stix_object_type:
        return None

    common = {
        "created_by_ref": identity_id,
        "confidence": confidence,
        "custom_properties": custom_properties,
        "allow_custom": True,
    }
    if stix_object_type == "attack-pattern":
        return AttackPattern(
            name=name,
            external_references=attack_pattern_references(value, attributes),
            **common,
        )
    if stix_object_type == "threat-actor":
        return ThreatActor(name=name, **common)
    if stix_object_type == "intrusion-set":
        return IntrusionSet(name=name, **common)
    if stix_object_type == "malware":
        return Malware(
            name=name,
            is_family=bool(attributes.get("is_family", True)),
            **common,
        )
    if stix_object_type == "tool":
        return Tool(name=name, **common)
    if stix_object_type == "vulnerability":
        return Vulnerability(
            name=name,
            external_references=vulnerability_references(value),
            **common,
        )
    if stix_object_type == "identity":
        return Identity(
            name=name,
            identity_class=clean_string(attributes.get("identity_class")) or "class",
            **common,
        )
    if stix_object_type == "location":
        return Location(name=name, country=value or name, **common)
    if stix_object_type == "indicator":
        pattern = clean_string(attributes.get("pattern")) or value
        pattern_type = clean_string(attributes.get("pattern_type")) or "stix"
        if not pattern:
            return None
        return Indicator(
            name=name,
            pattern=pattern,
            pattern_type=pattern_type,
            valid_from=now,
            **common,
        )
    if stix_object_type == "note":
        content = clean_string(attributes.get("content")) or value
        if not content:
            return None
        return Note(
            abstract=name,
            content=content,
            object_refs=[identity_id],
            **common,
        )
    if stix_object_type == "observable":
        return observable_candidate_to_stix(candidate, custom_properties)
    return None


def observable_candidate_to_stix(candidate, custom_properties):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    observable_type = clean_string(attributes.get("observable_type")).lower()
    value = clean_string(candidate.get("value"))
    hash_algorithm = clean_string(attributes.get("hash_algorithm")).upper()
    if not value:
        return None
    if observable_type == "domain-name":
        return DomainName(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "url":
        return URL(value=value, custom_properties=custom_properties, allow_custom=True)
    if observable_type == "ipv4-addr":
        return IPv4Address(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "ipv6-addr":
        return IPv6Address(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "email-addr":
        return EmailAddress(
            value=value,
            custom_properties=custom_properties,
            allow_custom=True,
        )
    if observable_type == "file" and hash_algorithm:
        return File(
            hashes={normalize_hash_algorithm(hash_algorithm): value},
            custom_properties=custom_properties,
            allow_custom=True,
        )
    return None


def attack_pattern_references(value, attributes):
    stix_id = clean_string(attributes.get("stix_id"))
    references = []
    if value.upper().startswith("T"):
        references.append({"source_name": "mitre-attack", "external_id": value.upper()})
    if stix_id:
        references.append({"source_name": "mitre-attack", "url": stix_id})
    return references or None


def vulnerability_references(value):
    normalized = value.upper()
    if not normalized.startswith("CVE-"):
        return None
    return [{"source_name": "cve", "external_id": normalized}]


def graph_custom_properties(candidate):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    custom = {
        "x_narrowcti_candidate_fingerprint": clean_string(candidate.get("fingerprint")),
        "x_narrowcti_entity_type": clean_string(candidate.get("entity_type")),
        "x_narrowcti_source_key": clean_string(candidate.get("source_key")),
        "x_narrowcti_source_name": clean_string(candidate.get("source_name")),
        "x_narrowcti_source_field": clean_string(candidate.get("source_field")),
        "x_narrowcti_external_id": clean_string(candidate.get("external_id")),
        "x_narrowcti_proposed_relationship_type": clean_string(
            candidate.get("relationship_type")
        ),
        "x_narrowcti_relationship_source_type": first_clean_value(
            attributes.get("relationship_source_stix_object_type"),
            attributes.get("source_stix_object_type"),
            parent_cluster_stix_object_type(attributes),
        ),
        "x_narrowcti_relationship_source_value": first_clean_value(
            attributes.get("relationship_source_value"),
            attributes.get("source_value"),
            attributes.get("parent_cluster_value"),
        ),
        "x_narrowcti_relationship_source_field": first_clean_value(
            attributes.get("relationship_source_field"),
            attributes.get("parent_tag_name"),
            attributes.get("parent_cluster_uuid"),
        ),
    }
    return {key: value for key, value in custom.items() if value}


def graph_relationship_custom_properties(candidate, relationship_mode):
    custom = graph_custom_properties(candidate)
    custom["x_narrowcti_relationship_mode"] = relationship_mode
    return custom


def graph_relationship_endpoint(candidate, graph_object_ids, report_id, target_ref):
    relationship_type = clean_string(candidate.get("relationship_type")) or "related-to"
    source_key = graph_relationship_source_key(candidate)
    source_ref = graph_object_ids.get(source_key) if source_key else ""
    if (
        source_ref
        and source_ref != target_ref
        and relationship_type in SEMANTIC_RELATIONSHIP_TYPES
    ):
        return source_ref, relationship_type, "semantic"
    return report_id, "related-to", "report-context"


def graph_relationship_source_key(candidate):
    attributes = (
        candidate.get("attributes")
        if isinstance(candidate.get("attributes"), dict)
        else {}
    )
    source_type = first_clean_value(
        attributes.get("relationship_source_stix_object_type"),
        attributes.get("source_stix_object_type"),
        parent_cluster_stix_object_type(attributes),
    )
    source_value = first_clean_value(
        attributes.get("relationship_source_value"),
        attributes.get("source_value"),
        attributes.get("parent_cluster_value"),
    )
    if not source_type or not source_value:
        return None
    return (source_type.lower(), source_value.lower())


def parent_cluster_stix_object_type(attributes):
    kind = " ".join(
        clean_string(attributes.get(field)).casefold()
        for field in (
            "parent_cluster_type",
            "parent_galaxy_type",
            "parent_galaxy_name",
        )
        if clean_string(attributes.get(field))
    )
    if "attack-pattern" in kind or "mitre-attack-pattern" in kind:
        return "attack-pattern"
    if "intrusion-set" in kind:
        return "intrusion-set"
    if "threat-actor" in kind or "threat actor" in kind:
        return "threat-actor"
    if "malpedia" in kind or "ransomware" in kind or "malware" in kind:
        return "malware"
    if "tool" in kind:
        return "tool"
    if "sector" in kind:
        return "identity"
    if "country" in kind or "region" in kind:
        return "location"
    return ""


def first_clean_value(*values):
    for value in values:
        cleaned = clean_string(value)
        if cleaned:
            return cleaned
    return ""


def graph_object_key(candidate):
    return (
        clean_string(candidate.get("stix_object_type")).lower(),
        clean_string(candidate.get("value") or candidate.get("name")).lower(),
    )


def candidate_summary(candidate):
    return {
        key: value
        for key, value in {
            "entity_type": candidate.get("entity_type"),
            "value": candidate.get("value"),
            "stix_object_type": candidate.get("stix_object_type"),
            "relationship_type": candidate.get("relationship_type"),
        }.items()
        if value
    }


def normalize_hash_algorithm(value):
    aliases = {
        "SHA1": "SHA-1",
        "SHA-1": "SHA-1",
        "SHA256": "SHA-256",
        "SHA-256": "SHA-256",
        "MD5": "MD5",
    }
    return aliases.get(value, value)


def clamp_stix_confidence(value):
    try:
        confidence = int(value)
    except (TypeError, ValueError):
        confidence = 50
    return max(0, min(100, confidence))


def clean_string(value):
    return " ".join(str(value or "").strip().split())
