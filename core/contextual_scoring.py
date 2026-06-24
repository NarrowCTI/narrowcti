from collections import Counter
from collections.abc import Mapping

from core.scoring import clamp_score


CONTEXTUAL_SCORING_VERSION = "v0.7.0-dev"

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
    mode="dry-run",
    enabled=True,
    category_impacts=None,
    max_impact=100,
):
    base_score = clamp_score(coerce_int(base_score, 50))
    mode = clean_string(mode) or "dry-run"
    max_impact = max(0, coerce_int(max_impact, 100))
    if not enabled:
        return contextual_score_result(
            base_score=base_score,
            contextual_score=base_score,
            mode=mode,
            status="disabled",
            adjustments=[],
            accepted_candidate_count=accepted_candidate_count(graph_candidate_policy),
            raw_impact_total=0,
            capped_impact_total=0,
            max_impact=max_impact,
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
):
    category_counts = Counter(adjustment["category"] for adjustment in adjustments)
    return {
        "version": CONTEXTUAL_SCORING_VERSION,
        "mode": mode,
        "status": status,
        "applied_to_decision": False,
        "base_score": base_score,
        "contextual_score": contextual_score,
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
