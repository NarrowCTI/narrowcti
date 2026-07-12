from collections import Counter
from collections.abc import Mapping

from core.scoring import clamp_score


CONTEXTUAL_SCORING_VERSION = "v1.0.0"
CONTEXTUAL_SCORING_MODES = ("off", "shadow", "enforce")
CONTEXTUAL_SCORING_MODE_ALIASES = {
    "audit": "shadow",
    "disabled": "off",
    "dry-run": "shadow",
    "dry_run": "shadow",
}

CATEGORY_BY_ENTITY_TYPE = {
    "threat_actor": "threat",
    "intrusion_set": "threat",
    "malware": "toolbox",
    "tool": "toolbox",
    "detection_rule": "toolbox",
    "attack_pattern": "ttp",
    "attack_tactic": "ttp",
    "attack_platform": "ttp",
    "attack_data_source": "ttp",
    "detection_guidance": "ttp",
    "target_sector": "sector",
    "target_country": "location",
    "target_region": "location",
    "vulnerability": "vulnerability",
    "source_identity": "author",
    "collector": "author",
    "observable": "graph_state",
    "sighting": "graph_state",
    "object_reference": "graph_state",
}

DEFAULT_CATEGORY_IMPACTS = {
    "threat": 20,
    "toolbox": 15,
    "ttp": 15,
    "sector": 10,
    "location": 10,
    "vulnerability": 15,
    "author": 5,
    "graph_state": 5,
}


def build_contextual_score_evidence(
    base_score,
    graph_candidate_policy,
    mode="shadow",
    enabled=True,
    category_impacts=None,
    max_impact=100,
):
    base_score = clamp_score(coerce_int(base_score, 50))
    mode = normalize_contextual_scoring_mode(mode)
    max_impact = normalize_contextual_scoring_max_impact(max_impact)
    if not enabled or mode == "off":
        return contextual_score_result(
            base_score=base_score,
            contextual_score=base_score,
            mode=mode,
            status="disabled" if not enabled else "off",
            adjustments=[],
            accepted_candidate_count=accepted_candidate_count(graph_candidate_policy),
            raw_impact_total=0,
            capped_impact_total=0,
            max_impact=max_impact,
            applied_to_decision=False,
        )

    impacts = normalize_category_impacts(category_impacts)
    adjustments, duplicate_count = contextual_adjustments(
        accepted_candidates(graph_candidate_policy),
        impacts,
    )
    raw_impact_total = sum(adjustment["impact"] for adjustment in adjustments)
    capped_impact_total = min(raw_impact_total, max_impact)
    impact_ratio = capped_impact_total / 100
    contextual_score = clamp_score(
        round(base_score + ((100 - base_score) * impact_ratio))
    )
    result = contextual_score_result(
        base_score=base_score,
        contextual_score=contextual_score,
        mode=mode,
        status=mode,
        adjustments=adjustments,
        accepted_candidate_count=accepted_candidate_count(graph_candidate_policy),
        raw_impact_total=raw_impact_total,
        capped_impact_total=capped_impact_total,
        max_impact=max_impact,
        applied_to_decision=mode == "enforce",
    )
    result["deduplicated_adjustment_count"] = duplicate_count
    return result


def contextual_adjustments(candidates, impacts):
    seen = set()
    adjustments = []
    duplicate_count = 0
    for candidate in candidates:
        entity_type = clean_string(candidate.get("entity_type"))
        category = CATEGORY_BY_ENTITY_TYPE.get(entity_type)
        if not category:
            continue
        value = clean_string(candidate.get("value") or candidate.get("name"))
        if not value:
            continue
        key = (category, entity_type, value.casefold())
        if key in seen:
            duplicate_count += 1
            continue
        seen.add(key)
        impact = impacts.get(category, 0)
        adjustments.append(
            {
                "category": category,
                "priority": "observed",
                "impact": impact,
                "matched_value": value,
                "entity_type": entity_type,
                "stix_object_type": clean_string(candidate.get("stix_object_type")),
                "relationship_type": clean_string(candidate.get("relationship_type")),
                "source_field": clean_string(candidate.get("source_field")),
                "reason": f"{category} context observed in accepted graph candidate",
            }
        )
    return adjustments, duplicate_count


def contextual_score_result(
    base_score,
    contextual_score,
    mode,
    status,
    adjustments,
    accepted_candidate_count,
    raw_impact_total,
    capped_impact_total,
    max_impact,
    applied_to_decision,
):
    category_counts = Counter(adjustment["category"] for adjustment in adjustments)
    decision_score = contextual_score if applied_to_decision else base_score
    return {
        "version": CONTEXTUAL_SCORING_VERSION,
        "mode": mode,
        "status": status,
        "configured_to_apply": mode == "enforce",
        "applied_to_decision": applied_to_decision,
        "base_score": base_score,
        "contextual_score": contextual_score,
        "decision_score": decision_score,
        "score_delta": max(0, contextual_score - base_score),
        "accepted_candidate_count": accepted_candidate_count,
        "adjustment_count": len(adjustments),
        "category_counts": dict(sorted(category_counts.items())),
        "raw_impact_total": raw_impact_total,
        "capped_impact_total": capped_impact_total,
        "max_impact": max_impact,
        "impact_ratio": capped_impact_total / 100,
        "capped": raw_impact_total > capped_impact_total,
        "adjustments": adjustments,
    }


def finalize_contextual_score_evidence(
    evidence,
    decision_score,
    decision_action,
    decision_reason,
):
    if not isinstance(evidence, Mapping):
        return {}
    result = dict(evidence)
    actual_score = clamp_score(
        coerce_int(decision_score, result.get("base_score", 50))
    )
    result["decision_score"] = actual_score
    result["applied_to_decision"] = bool(
        result.get("configured_to_apply")
        and actual_score == result.get("contextual_score")
        and actual_score != result.get("base_score")
    )
    result["decision_action"] = clean_string(decision_action)
    result["decision_reason"] = clean_string(decision_reason)
    return result


def normalize_contextual_scoring_mode(value):
    mode = clean_string(value).lower() or "shadow"
    mode = CONTEXTUAL_SCORING_MODE_ALIASES.get(mode, mode)
    if mode not in CONTEXTUAL_SCORING_MODES:
        raise ValueError(
            "contextual scoring mode must be off, shadow or enforce"
        )
    return mode


def normalize_contextual_scoring_max_impact(value):
    max_impact = coerce_int(value, 100)
    if max_impact < 0 or max_impact > 100:
        raise ValueError("contextual scoring max impact must be between 0 and 100")
    return max_impact


def parse_contextual_scoring_impacts(value):
    if value is None or value == "":
        return {}
    if isinstance(value, Mapping):
        entries = value.items()
    else:
        pairs = []
        for item in str(value).split(","):
            item = item.strip()
            if not item:
                continue
            if ":" not in item:
                raise ValueError(
                    "contextual scoring impacts must use category:points pairs"
                )
            category, impact = item.split(":", 1)
            pairs.append((category, impact))
        entries = pairs

    impacts = {}
    for category, impact in entries:
        normalized_category = clean_string(category).lower()
        if normalized_category not in DEFAULT_CATEGORY_IMPACTS:
            raise ValueError(
                f"unknown contextual scoring category: {normalized_category}"
            )
        normalized_impact = coerce_int(impact, 0)
        if normalized_impact < 0 or normalized_impact > 100:
            raise ValueError(
                "contextual scoring category impact must be between 0 and 100"
            )
        impacts[normalized_category] = normalized_impact
    return impacts


def contextual_scoring_config_from_settings(settings):
    return {
        "mode": normalize_contextual_scoring_mode(
            getattr(settings, "contextual_scoring_mode", "shadow")
        ),
        "category_impacts": parse_contextual_scoring_impacts(
            getattr(settings, "contextual_scoring_impacts", {})
        ),
        "max_impact": normalize_contextual_scoring_max_impact(
            getattr(settings, "contextual_scoring_max_impact", 100)
        ),
    }


def accepted_candidates(graph_candidate_policy):
    policy = graph_candidate_policy if isinstance(graph_candidate_policy, Mapping) else {}
    return [
        candidate
        for candidate in policy.get("accepted") or []
        if isinstance(candidate, Mapping)
    ]


def accepted_candidate_count(graph_candidate_policy):
    policy = graph_candidate_policy if isinstance(graph_candidate_policy, Mapping) else {}
    try:
        return int(policy.get("accepted_count", len(accepted_candidates(policy))))
    except (TypeError, ValueError):
        return len(accepted_candidates(policy))


def normalize_category_impacts(category_impacts):
    impacts = dict(DEFAULT_CATEGORY_IMPACTS)
    if isinstance(category_impacts, Mapping):
        for category, impact in category_impacts.items():
            normalized_category = clean_string(category).lower()
            if normalized_category:
                impacts[normalized_category] = max(0, coerce_int(impact, 0))
    return impacts


def coerce_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clean_string(value):
    return " ".join(str(value or "").strip().split())
