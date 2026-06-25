from collections import Counter
from collections.abc import Mapping
from hashlib import sha256

from core.graph_candidates import GRAPH_CANDIDATE_VERSION


GRAPH_EXPORT_PLAN_VERSION = GRAPH_CANDIDATE_VERSION
GRAPH_EXPORT_MODES = ("audit", "dry-run", "export")


def normalize_graph_export_mode(mode):
    normalized = clean_string(mode).lower() or "audit"
    aliases = {
        "dry_run": "dry-run",
        "dryrun": "dry-run",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in GRAPH_EXPORT_MODES:
        raise ValueError(
            "graph export mode must be one of: " + ", ".join(GRAPH_EXPORT_MODES)
        )
    return normalized


def build_graph_export_plan(
    graph_candidate_policy,
    mode="audit",
    known_entity_keys=None,
    known_relationship_keys=None,
):
    mode = normalize_graph_export_mode(mode)
    policy = graph_candidate_policy if isinstance(graph_candidate_policy, Mapping) else {}
    accepted = clean_candidates(policy.get("accepted"))
    held = clean_held(policy.get("held"))
    accepted_actions = planned_accepted_actions(
        accepted,
        mode,
        known_entity_keys=known_entity_keys,
        known_relationship_keys=known_relationship_keys,
    )

    actions = []
    actions.extend(accepted_actions)
    for item in held:
        actions.append(
            {
                "action": "held",
                "reasons": list(item.get("reasons") or []),
                "candidate": candidate_summary(item.get("candidate")),
            }
        )

    would_create = mode == "dry-run"
    create_actions = [
        action for action in accepted_actions if action.get("action") == "would_create"
    ]
    export_actions = [
        action for action in accepted_actions if action.get("action") == "exported"
    ]
    duplicate_actions = [
        action
        for action in accepted_actions
        if action.get("deduplication", {}).get("entity_duplicate")
        or action.get("deduplication", {}).get("relationship_duplicate")
    ]
    return {
        "version": GRAPH_EXPORT_PLAN_VERSION,
        "mode": mode,
        "status": plan_status(mode),
        "export_enabled": mode == "export",
        "candidate_count": int(
            policy.get("candidate_count") or len(accepted) + len(held)
        ),
        "accepted_count": len(accepted),
        "held_count": len(held),
        "held_reasons": held_reason_counts(policy, held),
        "accepted_object_counts": count_field(accepted, "stix_object_type"),
        "accepted_relationship_counts": count_field(accepted, "relationship_type"),
        "deduplicated_candidate_count": len(duplicate_actions),
        "deduplicated_entity_count": count_deduplicated(
            duplicate_actions,
            "entity_duplicate",
        ),
        "deduplicated_relationship_count": count_deduplicated(
            duplicate_actions,
            "relationship_duplicate",
        ),
        "would_create_object_count": len(
            [
                action
                for action in create_actions
                if not action.get("deduplication", {}).get("entity_duplicate")
            ]
        )
        if would_create
        else 0,
        "would_create_relationship_count": len(
            [
                action
                for action in create_actions
                if action.get("deduplication", {}).get("relationship_key")
                and not action.get("deduplication", {}).get("relationship_duplicate")
            ]
        )
        if would_create
        else 0,
        "exported_object_count": len(
            [
                action
                for action in export_actions
                if not action.get("deduplication", {}).get("entity_duplicate")
            ]
        ),
        "exported_relationship_count": len(
            [
                action
                for action in export_actions
                if action.get("deduplication", {}).get("relationship_key")
                and not action.get("deduplication", {}).get(
                    "relationship_duplicate"
                )
            ]
        ),
        "actions": actions,
    }


def build_graph_export_plan_with_known_keys(
    graph_candidate_policy,
    mode="audit",
    graph_deduplication_index=None,
):
    plan = build_graph_export_plan(graph_candidate_policy, mode=mode)
    known = {"entity_keys": [], "relationship_keys": []}
    if not graph_deduplication_index:
        return plan, known, ""

    try:
        known = normalize_known_graph_keys(
            graph_deduplication_index.known_keys_for_plan(plan)
        )
    except Exception as exc:
        return plan, known, str(exc)

    if known["entity_keys"] or known["relationship_keys"]:
        plan = build_graph_export_plan(
            graph_candidate_policy,
            mode=mode,
            known_entity_keys=known["entity_keys"],
            known_relationship_keys=known["relationship_keys"],
        )
    return plan, known, ""


def planned_accepted_actions(
    accepted,
    mode,
    known_entity_keys=None,
    known_relationship_keys=None,
):
    entity_keys = {
        clean_string(key)
        for key in known_entity_keys or []
        if clean_string(key)
    }
    relationship_keys = {
        clean_string(key)
        for key in known_relationship_keys or []
        if clean_string(key)
    }
    actions = []

    for candidate in accepted:
        entity_key = graph_entity_key(candidate)
        relationship_key = graph_relationship_key(candidate, entity_key)
        entity_duplicate = entity_key in entity_keys if entity_key else False
        relationship_duplicate = (
            relationship_key in relationship_keys if relationship_key else False
        )
        if entity_key:
            entity_keys.add(entity_key)
        if relationship_key:
            relationship_keys.add(relationship_key)

        action = {
            "action": planned_accepted_action(
                mode,
                entity_duplicate=entity_duplicate,
                relationship_duplicate=relationship_duplicate,
            ),
            "reason": planned_accepted_reason(
                mode,
                entity_duplicate=entity_duplicate,
                relationship_duplicate=relationship_duplicate,
            ),
            "candidate": candidate_summary(candidate),
            "deduplication": {
                "entity_key": entity_key,
                "relationship_key": relationship_key,
                "entity_duplicate": entity_duplicate,
                "relationship_duplicate": relationship_duplicate,
            },
        }
        actions.append(action)

    return actions


def planned_accepted_action(mode, entity_duplicate=False, relationship_duplicate=False):
    if relationship_duplicate:
        return "deduplicated"
    if mode == "dry-run":
        return "would_create"
    if mode == "export":
        return "exported"
    return "audit_only"


def planned_accepted_reason(mode, entity_duplicate=False, relationship_duplicate=False):
    if entity_duplicate and relationship_duplicate:
        return "graph_plan_duplicate_entity_and_relationship"
    if entity_duplicate:
        return "graph_plan_duplicate_entity"
    if relationship_duplicate:
        return "graph_plan_duplicate_relationship"
    if mode == "dry-run":
        return "graph_export_dry_run"
    if mode == "export":
        return "graph_export_enabled"
    return "graph_export_mode_audit"


def count_deduplicated(actions, field):
    return len(
        [
            action
            for action in actions
            if action.get("deduplication", {}).get(field)
        ]
    )


def plan_status(mode):
    if mode == "dry-run":
        return "dry-run"
    if mode == "export":
        return "export"
    return "audit-only"


def exportable_graph_candidate_policy(
    graph_candidate_policy,
    graph_export_plan,
    known_graph_keys=None,
):
    policy = mapping_from(graph_candidate_policy)
    if not mapping_from(graph_export_plan).get("export_enabled"):
        return policy_with_accepted(policy, [])

    known = normalize_known_graph_keys(known_graph_keys or {})
    known_entity_keys = set(known["entity_keys"])
    known_relationship_keys = set(known["relationship_keys"])
    known_matches = known_matches_by_entity_key(known.get("matches"))
    accepted_by_fingerprint = {
        clean_string(candidate.get("fingerprint")): candidate
        for candidate in clean_candidates(policy.get("accepted"))
        if clean_string(candidate.get("fingerprint"))
    }
    accepted = []

    for action in plan_actions(graph_export_plan):
        if clean_string(action.get("action")) != "exported":
            continue
        deduplication = mapping_from(action.get("deduplication"))
        entity_key = clean_string(deduplication.get("entity_key"))
        relationship_key = clean_string(deduplication.get("relationship_key"))
        if relationship_key and relationship_key in known_relationship_keys:
            continue
        fingerprint = clean_string(
            mapping_from(action.get("candidate")).get("fingerprint")
        )
        candidate = accepted_by_fingerprint.get(fingerprint)
        if not candidate:
            continue
        if entity_key and entity_key in known_entity_keys:
            annotated = candidate_with_existing_opencti_ref(
                candidate,
                known_matches.get(entity_key),
            )
            if annotated:
                accepted.append(annotated)
            continue
        accepted.append(candidate)

    return policy_with_accepted(policy, accepted)


def known_matches_by_entity_key(matches):
    indexed = {}
    for match in matches or []:
        match = mapping_from(match)
        entity_key = clean_string(match.get("entity_key"))
        if entity_key:
            indexed[entity_key] = match
    return indexed


def candidate_with_existing_opencti_ref(candidate, match):
    match = mapping_from(match)
    canonical = mapping_from(match.get("match"))
    existing_ref = clean_string(canonical.get("standard_id"))
    if not valid_existing_ref(existing_ref, candidate):
        return {}

    annotated = dict(candidate)
    attributes = mapping_from(annotated.get("attributes"))
    attributes["opencti_existing_ref"] = existing_ref
    for source_field, target_field in (
        ("opencti_id", "opencti_existing_id"),
        ("entity_type", "opencti_existing_entity_type"),
        ("name", "opencti_existing_name"),
        ("observable_value", "opencti_existing_observable_value"),
        ("match_type", "opencti_match_type"),
        ("match_value", "opencti_match_value"),
    ):
        value = clean_string(canonical.get(source_field))
        if value:
            attributes[target_field] = value
    annotated["attributes"] = attributes
    return annotated


def valid_existing_ref(existing_ref, candidate):
    if not existing_ref:
        return False
    return any(
        existing_ref.startswith(f"{prefix}--")
        for prefix in candidate_existing_ref_prefixes(candidate)
    )


def candidate_existing_ref_prefixes(candidate):
    candidate = mapping_from(candidate)
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    if stix_object_type != "observable":
        return [stix_object_type] if stix_object_type else []

    attributes = mapping_from(candidate.get("attributes"))
    observable_type = clean_string(attributes.get("observable_type")).lower()
    supported = {
        "domain-name",
        "email-addr",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "url",
    }
    return [observable_type] if observable_type in supported else []


def policy_with_accepted(policy, accepted):
    updated = dict(policy)
    updated["accepted"] = accepted
    updated["accepted_count"] = len(accepted)
    return updated


def plan_actions(plan):
    plan = mapping_from(plan)
    return [
        dict(action)
        for action in plan.get("actions") or []
        if isinstance(action, Mapping)
    ]


def clean_candidates(value):
    candidates = []
    for item in value or []:
        candidate = mapping_from(item)
        if candidate:
            candidates.append(candidate)
    return candidates


def clean_held(value):
    held = []
    for item in value or []:
        entry = mapping_from(item)
        candidate = mapping_from(entry.get("candidate"))
        if not candidate:
            continue
        held.append(
            {
                "candidate": candidate,
                "reasons": [
                    clean_string(reason)
                    for reason in entry.get("reasons") or []
                    if clean_string(reason)
                ],
            }
        )
    return held


def held_reason_counts(policy, held):
    if isinstance(policy.get("held_reasons"), Mapping):
        return dict(sorted(policy.get("held_reasons").items()))
    reasons = Counter()
    for item in held:
        for reason in item.get("reasons") or []:
            reasons[reason] += 1
    return dict(sorted(reasons.items()))


def count_field(candidates, field):
    return dict(
        sorted(
            Counter(
                clean_string(candidate.get(field))
                for candidate in candidates
                if clean_string(candidate.get(field))
            ).items()
        )
    )


def candidate_summary(candidate):
    candidate = mapping_from(candidate)
    summary = {}
    for field in (
        "fingerprint",
        "entity_type",
        "value",
        "name",
        "stix_object_type",
        "relationship_type",
        "confidence",
        "relationship_confidence",
        "external_id",
        "title",
    ):
        value = candidate.get(field)
        if value not in ("", None, [], {}):
            summary[field] = value
    provenance = mapping_from(candidate.get("provenance"))
    if provenance:
        summary["provenance"] = provenance
    return summary


def graph_entity_key(candidate):
    candidate = mapping_from(candidate)
    stix_object_type = clean_string(candidate.get("stix_object_type")).lower()
    value = normalized_key_value(candidate.get("value") or candidate.get("name"))
    if not stix_object_type or not value:
        return ""
    return stable_key("entity", stix_object_type, value)


def graph_relationship_key(candidate, entity_key=""):
    candidate = mapping_from(candidate)
    relationship_type = clean_string(candidate.get("relationship_type")).lower()
    if not relationship_type or not entity_key:
        return ""
    source_type, source_value = graph_relationship_source_anchor(candidate)
    return stable_key(
        "relationship",
        clean_string(candidate.get("source_key")).lower(),
        clean_string(candidate.get("external_id")).lower(),
        relationship_type,
        source_type,
        source_value,
        entity_key,
    )


def graph_relationship_source_anchor(candidate):
    candidate = mapping_from(candidate)
    attributes = mapping_from(candidate.get("attributes"))
    source_type = first_clean_value(
        attributes.get("relationship_source_stix_object_type"),
        attributes.get("source_stix_object_type"),
        parent_cluster_stix_object_type(attributes),
    ).lower()
    source_value = first_clean_value(
        attributes.get("relationship_source_value"),
        attributes.get("source_value"),
        attributes.get("parent_cluster_value"),
    ).lower()
    return source_type, source_value


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


def stable_key(*parts):
    material = "|".join(clean_string(part).lower() for part in parts)
    digest = sha256(material.encode("utf-8")).hexdigest()
    return f"{parts[0]}:{digest[:24]}"


def normalized_key_value(value):
    return clean_string(value).casefold()


def mapping_from(value):
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        return mapping_from(value.to_dict())
    return {}


def normalize_known_graph_keys(value):
    known = mapping_from(value)
    return {
        "entity_keys": [
            clean_string(key)
            for key in known.get("entity_keys") or []
            if clean_string(key)
        ],
        "relationship_keys": [
            clean_string(key)
            for key in known.get("relationship_keys") or []
            if clean_string(key)
        ],
        "matches": [
            summary
            for summary in (
                lookup_match_summary(match) for match in known.get("matches") or []
            )
            if summary
        ],
    }


def lookup_match_summary(value):
    match = mapping_from(value)
    if not match:
        return {}
    summary = {}
    for field in (
        "entity_key",
        "relationship_key",
        "stix_object_type",
        "value",
    ):
        cleaned = clean_string(match.get(field))
        if cleaned:
            summary[field] = cleaned

    canonical = mapping_from(match.get("match"))
    if canonical:
        canonical_summary = {}
        for field in (
            "opencti_id",
            "standard_id",
            "entity_type",
            "name",
            "observable_value",
            "x_mitre_id",
            "match_type",
            "match_value",
        ):
            cleaned = clean_string(canonical.get(field))
            if cleaned:
                canonical_summary[field] = cleaned
        if canonical_summary:
            summary["match"] = canonical_summary

    return summary


def clean_string(value):
    return " ".join(str(value or "").strip().split())
