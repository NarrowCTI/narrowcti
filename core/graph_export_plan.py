from collections import Counter
from collections.abc import Mapping

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


def build_graph_export_plan(graph_candidate_policy, mode="audit"):
    mode = normalize_graph_export_mode(mode)
    policy = graph_candidate_policy if isinstance(graph_candidate_policy, Mapping) else {}
    accepted = clean_candidates(policy.get("accepted"))
    held = clean_held(policy.get("held"))

    actions = []
    for candidate in accepted:
        actions.append(
            {
                "action": accepted_action(mode),
                "reason": accepted_reason(mode),
                "candidate": candidate_summary(candidate),
            }
        )
    for item in held:
        actions.append(
            {
                "action": "held",
                "reasons": list(item.get("reasons") or []),
                "candidate": candidate_summary(item.get("candidate")),
            }
        )

    would_create = mode == "dry-run"
    return {
        "version": GRAPH_EXPORT_PLAN_VERSION,
        "mode": mode,
        "status": plan_status(mode),
        "export_enabled": False,
        "candidate_count": int(
            policy.get("candidate_count") or len(accepted) + len(held)
        ),
        "accepted_count": len(accepted),
        "held_count": len(held),
        "held_reasons": held_reason_counts(policy, held),
        "accepted_object_counts": count_field(accepted, "stix_object_type"),
        "accepted_relationship_counts": count_field(accepted, "relationship_type"),
        "would_create_object_count": len(accepted) if would_create else 0,
        "would_create_relationship_count": (
            len([item for item in accepted if clean_string(item.get("relationship_type"))])
            if would_create
            else 0
        ),
        "actions": actions,
    }


def accepted_action(mode):
    if mode == "dry-run":
        return "would_create"
    if mode == "export":
        return "blocked"
    return "audit_only"


def accepted_reason(mode):
    if mode == "dry-run":
        return "graph_export_dry_run"
    if mode == "export":
        return "graph_export_not_implemented"
    return "graph_export_mode_audit"


def plan_status(mode):
    if mode == "dry-run":
        return "dry-run"
    if mode == "export":
        return "blocked"
    return "audit-only"


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


def mapping_from(value):
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        return mapping_from(value.to_dict())
    return {}


def clean_string(value):
    return " ".join(str(value or "").strip().split())
