import argparse
import copy
import html
import json
import os
from collections import Counter
from dataclasses import dataclass

from core.decision_audit import utc_now
from gateway.decisions import build_decision_audit_report, read_decision_records
from gateway.report import (
    build_operational_report,
    read_gateway_summary_file,
    read_quarantine_records,
)
from gateway.review import AnalystReviewService, ReviewSummary, read_audit_events
from gateway.settings import load_settings


REDACTION_PROFILES = ("none", "support", "external")
SCHEMA_VERSION = "curation-report/v0.8"
CONTEXT_SECTION_DEFINITIONS = (
    ("attack_patterns", "ATT&CK techniques", "top_attack_patterns"),
    ("arsenal", "Arsenal", "top_arsenal"),
    ("infrastructure", "Infrastructure and ASNs", "top_infrastructure"),
    ("threat_actors", "Threat actors and intrusion sets", "top_threat_actors"),
    ("target_sectors", "Target sectors", "top_target_sectors"),
)
REDACTION_POLICIES = {
    "none": {
        "audience": "local-operator",
        "raw_evidence_included": True,
        "aggregate_only": False,
        "removed_fields": [],
        "retained_sections": [
            "executive_summary",
            "operational",
            "decisions",
            "analyst_review",
            "analyst_review_actions",
            "source_summaries",
            "context_sections",
            "graph_validation",
            "policy_insights",
            "recommendations",
        ],
    },
    "support": {
        "audience": "support",
        "raw_evidence_included": False,
        "aggregate_only": True,
        "removed_fields": [
            "operational.failures",
            "operational.queries",
            "operational.sources.*.failures",
            "decisions.quarantined",
            "decisions.queries",
        ],
        "retained_sections": [
            "executive_summary",
            "source_summaries",
            "context_sections",
            "graph_validation",
            "policy_insights",
            "recommendations",
        ],
    },
    "external": {
        "audience": "external-recipient",
        "raw_evidence_included": False,
        "aggregate_only": True,
        "removed_fields": [
            "operational.failures",
            "operational.queries",
            "operational.sources.*.failures",
            "decisions.quarantined",
            "decisions.queries",
        ],
        "retained_sections": [
            "executive_summary",
            "source_summaries",
            "context_sections",
            "graph_validation",
            "policy_insights",
            "recommendations",
        ],
    },
}


@dataclass(frozen=True)
class CurationReport:
    schema_version: str
    generated_at: str
    executive_summary: dict
    operational: dict
    decisions: dict
    analyst_review: dict
    analyst_review_actions: dict
    source_summaries: list
    context_sections: dict
    graph_validation: dict
    policy_insights: list
    recommendations: list

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "executive_summary": self.executive_summary,
            "operational": self.operational,
            "decisions": self.decisions,
            "analyst_review": self.analyst_review,
            "analyst_review_actions": self.analyst_review_actions,
            "source_summaries": list(self.source_summaries),
            "context_sections": self.context_sections,
            "graph_validation": self.graph_validation,
            "policy_insights": list(self.policy_insights),
            "recommendations": list(self.recommendations),
        }


def build_curation_report(
    operational_report,
    decision_report,
    analyst_review_summary,
    analyst_review_actions=None,
    graph_validation=None,
    generated_at="",
):
    operational = operational_report.to_dict()
    decisions = decision_report.to_dict()
    analyst_review = analyst_review_summary.to_dict()
    review_actions = analyst_review_actions or empty_review_action_summary()
    executive = build_executive_summary(
        operational,
        decisions,
        analyst_review,
        review_actions,
    )
    source_summaries = build_source_summaries(
        operational,
        decisions,
        analyst_review,
        review_actions,
    )
    context_sections = build_context_sections(source_summaries)
    graph_validation = graph_validation or empty_graph_validation_summary()
    policy_insights = build_policy_insights(source_summaries)
    return CurationReport(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at or utc_now(),
        executive_summary=executive,
        operational=operational,
        decisions=decisions,
        analyst_review=analyst_review,
        analyst_review_actions=review_actions,
        source_summaries=source_summaries,
        context_sections=context_sections,
        graph_validation=graph_validation,
        policy_insights=policy_insights,
        recommendations=build_recommendations(
            executive,
            review_actions,
            policy_insights=policy_insights,
            graph_validation=graph_validation,
        ),
    )


def build_executive_summary(
    operational,
    decisions,
    analyst_review,
    review_actions=None,
):
    totals = operational.get("totals") or {}
    metrics = operational.get("metrics") or {}
    graph_export = decisions.get("graph_export") or {}
    graph_preview = decisions.get("graph_stix_preview") or {}
    actions = decisions.get("actions") or {}
    review_actions = review_actions or empty_review_action_summary()
    review_action_counts = review_actions.get("action_counts") or {}
    return {
        "run_count": operational.get("run_count", 0),
        "source_count": len(operational.get("sources") or {}),
        "decision_record_count": decisions.get("record_count", 0),
        "reviewed_count": int(totals.get("reviewed", 0) or 0),
        "accepted_count": int(metrics.get("accepted", 0) or 0),
        "filtered_count": int(metrics.get("filtered", 0) or 0),
        "error_count": int(metrics.get("errors", 0) or 0),
        "quarantine_decision_count": int(actions.get("quarantine", 0) or 0),
        "pending_review_count": analyst_review.get("pending_count", 0),
        "exportable_review_count": analyst_review.get("exportable_count", 0),
        "review_action_count": review_actions.get("event_count", 0),
        "review_release_count": review_action_counts.get("release", 0)
        + review_action_counts.get("release-indicators", 0),
        "review_reject_count": review_action_counts.get("reject", 0),
        "review_export_count": review_action_counts.get("export", 0),
        "review_release_rate_pct": review_actions.get("release_rate_pct", 0.0),
        "review_reject_rate_pct": review_actions.get("reject_rate_pct", 0.0),
        "acceptance_rate_pct": metrics.get("acceptance_rate_pct", 0.0),
        "filter_rate_pct": metrics.get("filter_rate_pct", 0.0),
        "error_rate_pct": metrics.get("error_rate_pct", 0.0),
        "graph_candidate_count": graph_export.get("candidate_count", 0),
        "graph_accepted_count": graph_export.get("accepted_count", 0),
        "graph_held_count": graph_export.get("held_count", 0),
        "graph_lookup_match_count": graph_export.get("lookup_match_count", 0),
        "graph_would_create_object_count": graph_export.get(
            "would_create_object_count",
            0,
        ),
        "graph_would_create_relationship_count": graph_export.get(
            "would_create_relationship_count",
            0,
        ),
        "graph_stix_bundle_count": graph_preview_int(
            graph_preview,
            "bundle_count",
            "record_count",
        ),
        "graph_stix_object_count": graph_preview_int(
            graph_preview,
            "graph_object_count",
            "object_count",
        ),
        "graph_stix_relationship_count": graph_preview_int(
            graph_preview,
            "graph_relationship_count",
            "relationship_count",
        ),
    }


def build_recommendations(
    summary,
    review_actions=None,
    policy_insights=None,
    graph_validation=None,
):
    recommendations = []
    review_actions = review_actions or empty_review_action_summary()
    policy_insights = policy_insights or []
    if summary.get("decision_record_count", 0) == 0 and summary.get("run_count", 0) == 0:
        recommendations.append(
            recommendation(
                "collect-evidence",
                "Run the gateway in dry-run mode and collect summary and decision audit evidence.",
            )
        )
    if summary.get("error_count", 0) > 0:
        recommendations.append(
            recommendation(
                "review-source-errors",
                "Investigate source errors before enabling continuous operation.",
            )
        )
    if summary.get("pending_review_count", 0) > 0:
        recommendations.append(
            recommendation(
                "review-quarantine",
                "Review pending quarantine records before promoting broader ingestion.",
            )
        )
    if summary.get("graph_would_create_object_count", 0) > 0:
        recommendations.append(
            recommendation(
                "validate-graph-promotion",
                "Validate graph dry-run objects and relationships in OpenCTI before export mode.",
            )
        )
    if summary.get("graph_lookup_match_count", 0) > 0:
        recommendations.append(
            recommendation(
                "preserve-graph-hygiene",
                "Keep OpenCTI graph lookup enabled for canonical object matching.",
            )
        )
    review_decisions = (
        summary.get("review_release_count", 0)
        + summary.get("review_reject_count", 0)
    )
    if review_decisions >= 3 and summary.get("review_reject_count", 0) > summary.get(
        "review_release_count",
        0,
    ):
        recommendations.append(
            recommendation(
                "tune-curation-policy",
                "Rejected quarantine releases exceed accepted releases; review thresholds, source scope and allowed context filters.",
            )
        )
    if (
        review_actions.get("event_count", 0) > 0
        and summary.get("pending_review_count", 0) > 0
    ):
        recommendations.append(
            recommendation(
                "continue-review-cycle",
                "Review actions exist but pending records remain; continue queue triage before broadening ingestion.",
            )
        )
    if any(insight.get("severity") == "high" for insight in policy_insights):
        recommendations.append(
            recommendation(
                "review-source-policy-insights",
                "Source-level review patterns indicate policy tuning may be needed before broader promotion.",
            )
        )
    relationship_audit = (graph_validation or {}).get("relationship_audit") or {}
    if (
        relationship_audit.get("available")
        and relationship_audit.get("coverage_status") == "needs-evidence"
    ):
        recommendations.append(
            recommendation(
                "complete-opencti-relationship-coverage",
                "OpenCTI relationship audit found promoted graph evidence, but expected Diamond or Kill Chain coverage is still incomplete.",
            )
        )
    return recommendations


def recommendation(code, message):
    return {
        "code": code,
        "message": message,
    }


def build_curation_report_from_files(
    summary_file="",
    decision_paths=None,
    quarantine_file="",
    release_audit_file="",
    relationship_audit_file="",
    limit=0,
):
    summary_records = safe_read_gateway_summary_file(summary_file, limit=limit)
    quarantine_records = read_quarantine_records(quarantine_file) if quarantine_file else []
    operational = build_operational_report(
        summary_records,
        quarantine_records=quarantine_records,
    )
    decision_records = read_decision_records(decision_paths or (), limit=limit or None)
    decisions = build_decision_audit_report(decision_records)
    review_summary = build_review_summary(quarantine_file, release_audit_file)
    review_actions = build_review_action_summary(
        safe_read_audit_events(release_audit_file, limit=limit),
    )
    graph_validation = build_graph_validation_summary(
        load_relationship_audit_evidence(relationship_audit_file)
    )
    return build_curation_report(
        operational,
        decisions,
        review_summary,
        analyst_review_actions=review_actions,
        graph_validation=graph_validation,
    )


def safe_read_gateway_summary_file(summary_file, limit=0):
    if not summary_file or not os.path.exists(summary_file):
        return []
    return read_gateway_summary_file(summary_file, limit=limit or None)


def build_review_summary(quarantine_file="", release_audit_file=""):
    if not quarantine_file or not os.path.exists(quarantine_file):
        return ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )
    return AnalystReviewService.from_paths(
        quarantine_file,
        release_audit_file=release_audit_file,
    ).summary()


def safe_read_audit_events(release_audit_file="", limit=0):
    if not release_audit_file or not os.path.exists(release_audit_file):
        return []
    events = read_audit_events(release_audit_file)
    if limit and limit > 0:
        return events[-limit:]
    return events


def load_relationship_audit_evidence(evidence_file):
    evidence_file = str(evidence_file or "").strip()
    if not evidence_file or not os.path.exists(evidence_file):
        return {}
    with open(evidence_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("relationship audit evidence file must contain a JSON object")
    return data


def empty_graph_validation_summary():
    return {
        "relationship_audit": {
            "available": False,
            "found": False,
            "target": {},
            "relationship_count": 0,
            "outbound_count": 0,
            "inbound_count": 0,
            "diamond_quadrant_counts": {},
            "coverage_status": "not-collected",
            "expected_quadrants": [],
            "present_quadrants": [],
            "missing_quadrants": [],
            "kill_chain_required": False,
            "kill_chain_present": False,
            "kill_chain_attack_pattern_count": 0,
        }
    }


def build_graph_validation_summary(relationship_audit_evidence=None):
    evidence = (
        relationship_audit_evidence
        if isinstance(relationship_audit_evidence, dict)
        else {}
    )
    if not evidence:
        return empty_graph_validation_summary()
    target = evidence.get("target") or {}
    coverage = evidence.get("coverage") or {}
    return {
        "relationship_audit": {
            "available": True,
            "found": bool(evidence.get("found", False)),
            "target": compact_audit_target(target),
            "relationship_count": int(evidence.get("relationship_count", 0) or 0),
            "outbound_count": int(evidence.get("outbound_count", 0) or 0),
            "inbound_count": int(evidence.get("inbound_count", 0) or 0),
            "diamond_quadrant_counts": {
                str(key): int(value or 0)
                for key, value in (
                    evidence.get("diamond_quadrant_counts") or {}
                ).items()
            },
            "coverage_status": str(coverage.get("status") or "informational"),
            "expected_quadrants": sorted_text_values(
                coverage.get("expected_quadrants")
            ),
            "present_quadrants": sorted_text_values(coverage.get("present_quadrants")),
            "missing_quadrants": sorted_text_values(coverage.get("missing_quadrants")),
            "kill_chain_required": bool(coverage.get("kill_chain_required", False)),
            "kill_chain_present": bool(coverage.get("kill_chain_present", False)),
            "kill_chain_attack_pattern_count": len(
                evidence.get("kill_chain_attack_patterns") or []
            ),
        }
    }


def compact_audit_target(target):
    if not isinstance(target, dict):
        return {}
    return {
        key: str(target.get(key) or "")
        for key in ("id", "standard_id", "entity_type", "name", "observable_value")
        if target.get(key)
    }


def sorted_text_values(values):
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",")]
    return sorted(str(value) for value in values or [] if str(value or "").strip())


def build_review_action_summary(events):
    action_counts = {}
    source_counts = {}
    source_action_counts = {}
    reason_counts = {}
    source_reason_counts = {}
    released_indicator_count = 0
    exported_indicator_count = 0
    dedup_duplicate_count = 0
    for event in events or []:
        action = normalize_count_key(event.get("action"), "unknown")
        source_key = normalize_count_key(event.get("source_key"), "(unknown)")
        reason = normalize_reason(event.get("reason"))
        action_counts[action] = action_counts.get(action, 0) + 1
        source_counts[source_key] = source_counts.get(source_key, 0) + 1
        source_actions = source_action_counts.setdefault(source_key, {})
        source_actions[action] = source_actions.get(action, 0) + 1
        reason_counts.setdefault(action, Counter())[reason] += 1
        source_reason_counts.setdefault(source_key, {}).setdefault(action, Counter())[
            reason
        ] += 1
        released_indicator_count += int(event.get("released_indicator_count", 0) or 0)
        exported_indicator_count += int(event.get("exported_indicator_count", 0) or 0)
        dedup_duplicate_count += int(event.get("dedup_duplicate_count", 0) or 0)

    release_count = action_counts.get("release", 0) + action_counts.get(
        "release-indicators",
        0,
    )
    reject_count = action_counts.get("reject", 0)
    review_decision_count = release_count + reject_count
    return {
        "event_count": len(events or []),
        "action_counts": dict(sorted(action_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "source_action_counts": {
            source: dict(sorted(actions.items()))
            for source, actions in sorted(source_action_counts.items())
        },
        "top_reasons": {
            action: top_reason_entries(counter)
            for action, counter in sorted(reason_counts.items())
        },
        "source_top_reasons": {
            source: {
                action: top_reason_entries(counter)
                for action, counter in sorted(action_reasons.items())
            }
            for source, action_reasons in sorted(source_reason_counts.items())
        },
        "released_indicator_count": released_indicator_count,
        "exported_indicator_count": exported_indicator_count,
        "dedup_duplicate_count": dedup_duplicate_count,
        "review_decision_count": review_decision_count,
        "release_rate_pct": percent(release_count, review_decision_count),
        "reject_rate_pct": percent(reject_count, review_decision_count),
    }


def empty_review_action_summary():
    return build_review_action_summary([])


def empty_score_summary():
    return {
        "records_with_score": 0,
        "min_score": None,
        "max_score": None,
        "average_score": None,
        "bands": {},
    }


def empty_graph_evidence_summary():
    return {
        "decision_records": 0,
        "candidate_count": 0,
        "accepted_count": 0,
        "held_count": 0,
        "lookup_match_count": 0,
        "would_create_object_count": 0,
        "would_create_relationship_count": 0,
        "stix_object_count": 0,
        "stix_relationship_count": 0,
        "candidate_density": 0.0,
        "relationship_density": 0.0,
        "lookup_match_rate_pct": 0.0,
        "top_accepted_objects": [],
        "top_accepted_relationships": [],
        "top_lookup_objects": [],
        "top_stix_objects": [],
        "top_stix_relationships": [],
    }


def empty_context_quality_summary():
    return {
        "record_count": 0,
        "accepted_candidate_count": 0,
        "adjustment_count": 0,
        "score_delta_total": 0,
        "average_score_delta": None,
        "max_contextual_score": None,
        "capped_count": 0,
        "applied_to_decision_count": 0,
        "candidate_density": 0.0,
        "category_diversity": 0,
        "category_counts": {},
        "top_categories": [],
    }


def empty_context_narrative_summary():
    return {
        "record_count": 0,
        "entity_count": 0,
        "counts": {
            "attack_patterns": 0,
            "arsenal": 0,
            "infrastructure": 0,
            "target_sectors": 0,
            "threat_actors": 0,
        },
        "overlap_counts": {},
        "top_attack_patterns": [],
        "top_arsenal": [],
        "top_infrastructure": [],
        "top_threat_actors": [],
        "top_target_sectors": [],
    }


def build_graph_evidence_summary(graph_export, graph_preview, decision_records):
    graph_export = graph_export or {}
    graph_preview = graph_preview or {}
    decision_records = int(decision_records or 0)
    candidate_count = int(graph_export.get("candidate_count", 0) or 0)
    accepted_count = int(graph_export.get("accepted_count", 0) or 0)
    lookup_match_count = int(graph_export.get("lookup_match_count", 0) or 0)
    would_create_relationship_count = int(
        graph_export.get("would_create_relationship_count", 0) or 0
    )
    stix_relationship_count = graph_preview_int(
        graph_preview,
        "graph_relationship_count",
        "relationship_count",
    )
    accepted_object_counts = graph_export.get("accepted_object_counts") or {}
    accepted_relationship_counts = graph_export.get("accepted_relationship_counts") or {}
    lookup_object_counts = graph_export.get("lookup_match_object_counts") or {}
    stix_object_counts = graph_preview.get("object_counts") or {}
    stix_relationship_counts = graph_preview.get("relationship_counts") or {}
    return {
        "decision_records": decision_records,
        "candidate_count": candidate_count,
        "accepted_count": accepted_count,
        "held_count": int(graph_export.get("held_count", 0) or 0),
        "lookup_match_count": lookup_match_count,
        "would_create_object_count": int(
            graph_export.get("would_create_object_count", 0) or 0
        ),
        "would_create_relationship_count": would_create_relationship_count,
        "stix_object_count": graph_preview_int(
            graph_preview,
            "graph_object_count",
            "object_count",
        ),
        "stix_relationship_count": stix_relationship_count,
        "candidate_density": ratio(candidate_count, decision_records),
        "relationship_density": ratio(
            would_create_relationship_count + stix_relationship_count,
            candidate_count,
        ),
        "lookup_match_rate_pct": percent(lookup_match_count, accepted_count),
        "top_accepted_objects": top_count_entries(accepted_object_counts),
        "top_accepted_relationships": top_count_entries(accepted_relationship_counts),
        "top_lookup_objects": top_count_entries(lookup_object_counts),
        "top_stix_objects": top_count_entries(stix_object_counts),
        "top_stix_relationships": top_count_entries(stix_relationship_counts),
    }


def build_context_quality_summary(contextual_scoring, decision_records):
    contextual_scoring = contextual_scoring or {}
    decision_records = int(decision_records or 0)
    category_counts = dict(contextual_scoring.get("category_counts") or {})
    accepted_candidate_count = int(
        contextual_scoring.get("accepted_candidate_count", 0) or 0
    )
    return {
        "record_count": int(contextual_scoring.get("record_count", 0) or 0),
        "accepted_candidate_count": accepted_candidate_count,
        "adjustment_count": int(contextual_scoring.get("adjustment_count", 0) or 0),
        "score_delta_total": int(contextual_scoring.get("score_delta_total", 0) or 0),
        "average_score_delta": contextual_scoring.get("average_score_delta"),
        "max_contextual_score": contextual_scoring.get("max_contextual_score"),
        "capped_count": int(contextual_scoring.get("capped_count", 0) or 0),
        "applied_to_decision_count": int(
            contextual_scoring.get("applied_to_decision_count", 0) or 0
        ),
        "candidate_density": ratio(accepted_candidate_count, decision_records),
        "category_diversity": len(category_counts),
        "category_counts": category_counts,
        "top_categories": top_category_entries(category_counts),
    }


def build_context_narrative_summary(graph_entities):
    graph_entities = graph_entities or {}
    counts = dict(graph_entities.get("counts") or {})
    return {
        "record_count": int(graph_entities.get("record_count", 0) or 0),
        "entity_count": int(graph_entities.get("entity_count", 0) or 0),
        "counts": {
            "attack_patterns": int(counts.get("attack_patterns", 0) or 0),
            "arsenal": int(counts.get("arsenal", 0) or 0),
            "infrastructure": int(counts.get("infrastructure", 0) or 0),
            "target_sectors": int(counts.get("target_sectors", 0) or 0),
            "threat_actors": int(counts.get("threat_actors", 0) or 0),
        },
        "overlap_counts": dict(graph_entities.get("overlap_counts") or {}),
        "top_attack_patterns": list(graph_entities.get("top_attack_patterns") or []),
        "top_arsenal": list(graph_entities.get("top_arsenal") or []),
        "top_infrastructure": list(graph_entities.get("top_infrastructure") or []),
        "top_threat_actors": list(graph_entities.get("top_threat_actors") or []),
        "top_target_sectors": list(graph_entities.get("top_target_sectors") or []),
    }


def build_context_sections(source_summaries):
    return {
        category: build_context_section(source_summaries, category, label, field_name)
        for category, label, field_name in CONTEXT_SECTION_DEFINITIONS
    }


def build_context_section(source_summaries, category, label, field_name):
    entity_counts = Counter()
    entity_sources = {}
    source_entries = []
    source_keys = set()
    for source in source_summaries or []:
        narrative = source.get("context_narrative") or {}
        for item in narrative.get(field_name) or []:
            entry = context_section_entry(source, item)
            if not entry:
                continue
            source_keys.add(entry["source_key"])
            entity_counts[
                (
                    entry["entity_type"],
                    entry["value"],
                    entry["display_name"],
                )
            ] += entry["count"]
            entity_sources.setdefault(
                (
                    entry["entity_type"],
                    entry["value"],
                    entry["display_name"],
                ),
                set(),
            ).add(entry["source_key"])
            source_entries.append(entry)
    source_entries.sort(
        key=lambda item: (
            -int(item.get("count", 0) or 0),
            item.get("display_name", ""),
            item.get("source_key", ""),
            item.get("entity_type", ""),
        )
    )
    return {
        "category": category,
        "label": label,
        "source_count": len(source_keys),
        "distinct_entity_count": len(entity_counts),
        "observation_count": sum(entity_counts.values()),
        "top_entities": context_section_top_entities(entity_counts),
        "shared_entity_count": sum(1 for sources in entity_sources.values() if len(sources) > 1),
        "shared_entities": context_section_shared_entities(entity_counts, entity_sources),
        "source_entries": source_entries,
    }


def context_section_entry(source, item):
    count = int(item.get("count", 0) or 0)
    if count <= 0:
        return {}
    value = str(item.get("value") or item.get("display_name") or "").strip()
    display_name = str(item.get("display_name") or value).strip()
    if not value and not display_name:
        return {}
    return {
        "source_key": source.get("source_key", "(unknown)"),
        "source_name": source.get("source_name", source.get("source_key", "")),
        "entity_type": str(item.get("entity_type") or "unknown").strip() or "unknown",
        "value": value or display_name,
        "display_name": display_name or value,
        "count": count,
    }


def context_section_top_entities(counter, limit=10):
    items = sorted(
        (counter or {}).items(),
        key=lambda item: (-item[1], item[0][2], item[0][1], item[0][0]),
    )
    return [
        {
            "entity_type": entity_type,
            "value": value,
            "display_name": display_name,
            "count": count,
        }
        for (entity_type, value, display_name), count in items[:limit]
    ]


def context_section_shared_entities(counter, entity_sources, limit=10):
    shared = [
        (key, counter.get(key, 0), len(sources or ()))
        for key, sources in (entity_sources or {}).items()
        if len(sources or ()) > 1 and counter.get(key, 0) > 0
    ]
    shared.sort(
        key=lambda item: (
            -item[2],
            -item[1],
            context_entity_type_priority(item[0][0]),
            item[0][2],
            item[0][1],
            item[0][0],
        )
    )
    return [
        {
            "entity_type": entity_type,
            "value": value,
            "display_name": display_name,
            "count": count,
            "source_count": source_count,
        }
        for (entity_type, value, display_name), count, source_count in shared[:limit]
    ]


def context_entity_type_priority(entity_type):
    return {
        "autonomous_system": 0,
        "infrastructure": 1,
        "observable": 2,
    }.get(entity_type, 10)


def build_source_summaries(operational, decisions, analyst_review, review_actions):
    source_keys = set()
    source_keys.update((operational.get("sources") or {}).keys())
    source_keys.update((decisions.get("sources") or {}).keys())
    source_keys.update((analyst_review.get("source_counts") or {}).keys())
    source_keys.update((review_actions.get("source_counts") or {}).keys())
    source_keys.update(
        ((operational.get("quarantine_review") or {}).get("by_source") or {}).keys()
    )

    summaries = []
    for source_key in sorted(source_keys):
        operational_source = (operational.get("sources") or {}).get(source_key) or {}
        decision_source = (decisions.get("sources") or {}).get(source_key) or {}
        quarantine_source = (
            ((operational.get("quarantine_review") or {}).get("by_source") or {}).get(
                source_key,
            )
            or {}
        )
        review_action_counts = (
            (review_actions.get("source_action_counts") or {}).get(source_key) or {}
        )
        top_review_reasons = flatten_source_reasons(
            (review_actions.get("source_top_reasons") or {}).get(source_key) or {}
        )
        top_quarantine_reasons = source_action_reason_entries(
            decision_source.get("action_reasons") or {},
            "quarantine",
        )
        score_summary = decision_source.get("score_summary") or empty_score_summary()
        graph_evidence = build_graph_evidence_summary(
            ((decisions.get("graph_export") or {}).get("by_source") or {}).get(
                source_key,
            )
            or {},
            ((decisions.get("graph_stix_preview") or {}).get("by_source") or {}).get(
                source_key,
            )
            or {},
            decision_source.get("records", 0),
        )
        context_quality = build_context_quality_summary(
            ((decisions.get("contextual_scoring") or {}).get("by_source") or {}).get(
                source_key,
            )
            or {},
            decision_source.get("records", 0),
        )
        context_narrative = build_context_narrative_summary(
            ((decisions.get("graph_entities") or {}).get("by_source") or {}).get(
                source_key,
            )
            or {}
        )
        totals = operational_source.get("totals") or {}
        metrics = operational_source.get("metrics") or {}
        statuses = quarantine_source.get("statuses") or {}
        release_count = review_action_counts.get("release", 0) + review_action_counts.get(
            "release-indicators",
            0,
        )
        reject_count = review_action_counts.get("reject", 0)
        summary = {
            "source_key": source_key,
            "source_name": operational_source.get("source_name", source_key),
            "runs": operational_source.get("runs", 0),
            "succeeded": operational_source.get("succeeded", 0),
            "failed": operational_source.get("failed", 0),
            "reviewed": int(totals.get("reviewed", 0) or 0),
            "accepted": metrics.get("accepted", 0),
            "filtered": metrics.get("filtered", 0),
            "errors": metrics.get("errors", 0),
            "acceptance_rate_pct": metrics.get("acceptance_rate_pct", 0.0),
            "decision_records": decision_source.get("records", 0),
            "decision_actions": decision_source.get("actions") or {},
            "score_summary": score_summary,
            "average_score": score_summary.get("average_score"),
            "low_score_count": int((score_summary.get("bands") or {}).get("0-29", 0))
            + int((score_summary.get("bands") or {}).get("30-49", 0)),
            "graph_evidence": graph_evidence,
            "context_quality": context_quality,
            "context_narrative": context_narrative,
            "quarantine_records": quarantine_source.get("records", 0)
            or (analyst_review.get("source_counts") or {}).get(source_key, 0),
            "pending_review": statuses.get("pending", 0),
            "exportable_review": statuses.get("released", 0)
            + statuses.get("partially-released", 0),
            "review_actions": dict(sorted(review_action_counts.items())),
            "top_review_reasons": top_review_reasons,
            "top_quarantine_reasons": top_quarantine_reasons,
            "release_count": release_count,
            "reject_count": reject_count,
        }
        summary["posture"] = source_posture(summary)
        summaries.append(summary)
    return summaries


def source_posture(summary):
    if (
        summary.get("runs", 0) == 0
        and summary.get("decision_records", 0) == 0
        and summary.get("quarantine_records", 0) == 0
        and not summary.get("review_actions")
    ):
        return "no-evidence"
    if (
        summary.get("failed", 0) > 0
        or summary.get("errors", 0) > 0
        or summary.get("pending_review", 0) > 0
        or summary.get("reject_count", 0) > summary.get("release_count", 0)
    ):
        return "needs-attention"
    return "stable"


def build_policy_insights(source_summaries):
    insights = []
    for source in source_summaries or []:
        release_count = int(source.get("release_count", 0) or 0)
        reject_count = int(source.get("reject_count", 0) or 0)
        review_decision_count = release_count + reject_count
        if review_decision_count == 0:
            continue
        insight = {
            "source_key": source.get("source_key", "(unknown)"),
            "review_decision_count": review_decision_count,
            "release_count": release_count,
            "reject_count": reject_count,
            "release_rate_pct": percent(release_count, review_decision_count),
            "reject_rate_pct": percent(reject_count, review_decision_count),
            "top_reasons": source.get("top_review_reasons", []),
            "top_quarantine_reasons": source.get("top_quarantine_reasons", []),
            "score_summary": source.get("score_summary", empty_score_summary()),
            "average_score": source.get("average_score"),
            "low_score_count": source.get("low_score_count", 0),
            "graph_evidence": source.get(
                "graph_evidence",
                empty_graph_evidence_summary(),
            ),
            "context_quality": source.get(
                "context_quality",
                empty_context_quality_summary(),
            ),
            "context_narrative": source.get(
                "context_narrative",
                empty_context_narrative_summary(),
            ),
            "severity": "info",
            "signal": "observe-review-pattern",
            "message": "Review decisions exist; continue collecting evidence before changing policy.",
        }
        if review_decision_count >= 3 and reject_count > release_count:
            insight.update(
                {
                    "severity": "high",
                    "signal": "policy-too-permissive-or-source-too-noisy",
                    "message": "Rejected releases exceed accepted releases for this source; review score thresholds, TLP/date filters, source scope and context requirements.",
                }
            )
        elif review_decision_count >= 3 and release_count > reject_count:
            insight.update(
                {
                    "severity": "medium",
                    "signal": "policy-may-be-too-strict",
                    "message": "Accepted releases exceed rejected releases for this source; review whether quarantine thresholds or allow-list context are holding useful intelligence too often.",
                }
            )
        insights.append(insight)
    return insights


def normalize_count_key(value, default):
    text = str(value or "").strip()
    return text if text else default


def normalize_reason(value):
    return normalize_count_key(value, "(no reason)")


def top_reason_entries(counter, limit=3):
    items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return [
        {
            "reason": reason,
            "count": count,
        }
        for reason, count in items[:limit]
    ]


def top_category_entries(category_counts, limit=3):
    items = sorted(
        (category_counts or {}).items(),
        key=lambda item: (-int(item[1] or 0), item[0]),
    )
    return [
        {
            "category": category,
            "count": int(count or 0),
        }
        for category, count in items[:limit]
    ]


def top_count_entries(counts, limit=3):
    items = sorted(
        (counts or {}).items(),
        key=lambda item: (-int(item[1] or 0), str(item[0])),
    )
    return [
        {
            "type": str(item_type),
            "count": int(count or 0),
        }
        for item_type, count in items[:limit]
        if int(count or 0) > 0
    ]


def source_action_reason_entries(action_reasons, action, limit=3):
    reason_counts = (action_reasons or {}).get(action) or {}
    return [
        {
            "action": action,
            "reason": item["reason"],
            "count": item["count"],
        }
        for item in top_reason_entries(reason_counts, limit=limit)
    ]


def flatten_source_reasons(source_top_reasons):
    reasons = []
    for action, entries in sorted((source_top_reasons or {}).items()):
        if action not in {"release", "release-indicators", "reject"}:
            continue
        for entry in entries:
            reasons.append(
                {
                    "action": action,
                    "reason": entry.get("reason", "(no reason)"),
                    "count": int(entry.get("count", 0) or 0),
                }
            )
    return sorted(
        reasons,
        key=lambda item: (
            item["action"],
            -item["count"],
            item["reason"],
        ),
    )[:3]


def percent(value, total):
    if not total:
        return 0.0
    return round((float(value) / float(total)) * 100, 2)


def ratio(value, total):
    if not total:
        return 0.0
    return round(float(value) / float(total), 2)


def graph_preview_int(graph_preview, *keys):
    graph_preview = graph_preview or {}
    for key in keys:
        if key in graph_preview:
            return int(graph_preview.get(key, 0) or 0)
    return 0


def report_to_dict(report, redaction_profile="none"):
    data = report.to_dict()
    profile = normalize_redaction_profile(redaction_profile)
    data["redaction_profile"] = profile
    data["redaction_policy"] = redaction_policy_for_profile(profile)
    if profile == "none":
        return data
    return redact_report_dict(data)


def normalize_redaction_profile(value):
    profile = str(value or "none").strip().lower()
    if profile not in REDACTION_PROFILES:
        raise ValueError(
            "redaction_profile must be one of: " + ",".join(REDACTION_PROFILES)
        )
    return profile


def redaction_policy_for_profile(value):
    profile = normalize_redaction_profile(value)
    return copy.deepcopy(REDACTION_POLICIES[profile])


def redact_report_dict(report):
    redacted = copy.deepcopy(report)
    operational = redacted.get("operational") or {}
    operational["failures"] = []
    operational["queries"] = []
    for source in (operational.get("sources") or {}).values():
        if isinstance(source, dict):
            source["failures"] = []

    decisions = redacted.get("decisions") or {}
    decisions["quarantined"] = []
    decisions["queries"] = []
    return redacted


def format_text_report(report, redaction_profile="none"):
    data = report_to_dict(report, redaction_profile=redaction_profile)
    summary = data["executive_summary"]
    review_actions = data.get("analyst_review_actions") or {}
    redaction_policy = data.get("redaction_policy") or {}
    relationship_audit = (
        (data.get("graph_validation") or {}).get("relationship_audit") or {}
    )
    lines = [
        "NarrowCTI curation report",
        f"schema_version={data['schema_version']}",
        f"generated_at={data['generated_at']}",
        f"redaction_profile={data['redaction_profile']}",
        "redaction_policy:",
        f"- {format_redaction_policy(redaction_policy)}",
        "executive_summary:",
        "- "
        f"runs={summary['run_count']} "
        f"sources={summary['source_count']} "
        f"decision_records={summary['decision_record_count']} "
        f"reviewed={summary['reviewed_count']} "
        f"accepted={summary['accepted_count']} "
        f"filtered={summary['filtered_count']} "
        f"errors={summary['error_count']}",
        "- "
        f"acceptance_rate_pct={summary['acceptance_rate_pct']} "
        f"filter_rate_pct={summary['filter_rate_pct']} "
        f"error_rate_pct={summary['error_rate_pct']}",
        "analyst_review:",
        "- "
        f"pending={summary['pending_review_count']} "
        f"exportable={summary['exportable_review_count']} "
        f"quarantine_decisions={summary['quarantine_decision_count']}",
        "- "
        f"review_actions={summary['review_action_count']} "
        f"released={summary['review_release_count']} "
        f"rejected={summary['review_reject_count']} "
        f"exported={summary['review_export_count']} "
        f"release_rate_pct={summary['review_release_rate_pct']} "
        f"reject_rate_pct={summary['review_reject_rate_pct']}",
        "- "
        f"released_indicators={review_actions.get('released_indicator_count', 0)} "
        f"exported_indicators={review_actions.get('exported_indicator_count', 0)} "
        f"dedup_duplicates={review_actions.get('dedup_duplicate_count', 0)}",
        "graph_readiness:",
        "- "
        f"candidates={summary['graph_candidate_count']} "
        f"accepted={summary['graph_accepted_count']} "
        f"held={summary['graph_held_count']} "
        f"lookup_matches={summary['graph_lookup_match_count']} "
        f"would_create_objects={summary['graph_would_create_object_count']} "
        f"would_create_relationships="
        f"{summary['graph_would_create_relationship_count']}",
        "- "
        f"stix_bundles={summary['graph_stix_bundle_count']} "
        f"stix_objects={summary['graph_stix_object_count']} "
        f"stix_relationships={summary['graph_stix_relationship_count']}",
    ]
    if relationship_audit.get("available"):
        lines.append("graph_validation:")
        lines.append(
            "- "
            f"opencti_relationship_audit found="
            f"{str(relationship_audit.get('found', False)).lower()} "
            f"target={format_audit_target_summary(relationship_audit.get('target'))} "
            f"relationships={relationship_audit.get('relationship_count', 0)} "
            f"outbound={relationship_audit.get('outbound_count', 0)} "
            f"inbound={relationship_audit.get('inbound_count', 0)} "
            f"coverage={relationship_audit.get('coverage_status', '')} "
            f"present={format_text_values(relationship_audit.get('present_quadrants'))} "
            f"missing={format_text_values(relationship_audit.get('missing_quadrants'))} "
            f"quadrants="
            f"{format_mapping_counts(relationship_audit.get('diamond_quadrant_counts'))} "
            f"kill_chain_required="
            f"{str(relationship_audit.get('kill_chain_required', False)).lower()} "
            f"kill_chain_present="
            f"{str(relationship_audit.get('kill_chain_present', False)).lower()} "
            f"kill_chain_attack_patterns="
            f"{relationship_audit.get('kill_chain_attack_pattern_count', 0)}"
        )
    if data.get("context_sections"):
        lines.append("context_sections:")
        sections = sorted(
            (data.get("context_sections") or {}).values(),
            key=lambda item: item.get("category", ""),
        )
        for section in sections:
            lines.append(
                "- "
                f"{section.get('category')} "
                f"{format_context_section_summary(section)}"
            )
    if data.get("source_summaries"):
        lines.append("source_summaries:")
        for source in data["source_summaries"]:
            lines.append(
                "- "
                f"{source['source_key']} posture={source['posture']} "
                f"runs={source['runs']} failed={source['failed']} "
                f"reviewed={source['reviewed']} accepted={source['accepted']} "
                f"filtered={source['filtered']} errors={source['errors']} "
                f"decision_records={source['decision_records']} "
                f"pending_review={source['pending_review']} "
                f"release_count={source['release_count']} "
                f"reject_count={source['reject_count']} "
                f"narrative="
                f"{format_context_narrative_summary(source.get('context_narrative'))}"
            )
    if data.get("policy_insights"):
        lines.append("policy_insights:")
        for insight in data["policy_insights"]:
            lines.append(
                "- "
                f"{insight['source_key']} severity={insight['severity']} "
                f"signal={insight['signal']} "
                f"review_decisions={insight['review_decision_count']} "
                f"release_rate_pct={insight['release_rate_pct']} "
                f"reject_rate_pct={insight['reject_rate_pct']} "
                f"scores={format_policy_score_summary(insight.get('score_summary'))} "
                f"graph={format_graph_evidence_summary(insight.get('graph_evidence'))} "
                f"context={format_context_quality_summary(insight.get('context_quality'))} "
                f"narrative="
                f"{format_context_narrative_summary(insight.get('context_narrative'))} "
                f"quarantine_reasons="
                f"{format_reason_entries(insight.get('top_quarantine_reasons'))} "
                f"top_reasons={format_reason_entries(insight.get('top_reasons'))}: "
                f"{insight['message']}"
            )
    if data["recommendations"]:
        lines.append("recommendations:")
        for item in data["recommendations"]:
            lines.append(f"- {item['code']}: {item['message']}")
    return "\n".join(lines)


def format_html_report(report, redaction_profile="none"):
    data = report_to_dict(report, redaction_profile=redaction_profile)
    summary = data["executive_summary"]
    review_actions = data.get("analyst_review_actions") or {}
    redaction_policy = data.get("redaction_policy") or {}
    relationship_audit = (
        (data.get("graph_validation") or {}).get("relationship_audit") or {}
    )
    recommendations = "\n".join(
        "<li><strong>{}</strong>: {}</li>".format(
            escape(item.get("code")),
            escape(item.get("message")),
        )
        for item in data.get("recommendations") or []
    )
    if not recommendations:
        recommendations = "<li>none</li>"
    source_rows = "\n".join(
        html_table_row(
            source.get("source_key"),
            source.get("posture"),
            source.get("runs"),
            source.get("failed"),
            source.get("reviewed"),
            source.get("accepted"),
            source.get("filtered"),
            source.get("errors"),
            source.get("decision_records"),
            source.get("pending_review"),
            source.get("release_count"),
            source.get("reject_count"),
            format_context_narrative_summary(source.get("context_narrative")),
        )
        for source in data.get("source_summaries") or []
    )
    if not source_rows:
        source_rows = html_table_row("none", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "")
    policy_rows = "\n".join(
        html_table_row(
            insight.get("source_key"),
            insight.get("severity"),
            insight.get("signal"),
            insight.get("review_decision_count"),
            insight.get("release_count"),
            insight.get("reject_count"),
            insight.get("release_rate_pct"),
            insight.get("reject_rate_pct"),
            format_policy_score_summary(insight.get("score_summary")),
            format_graph_evidence_summary(insight.get("graph_evidence")),
            format_context_quality_summary(insight.get("context_quality")),
            format_context_narrative_summary(insight.get("context_narrative")),
            format_reason_entries(insight.get("top_quarantine_reasons")),
            format_reason_entries(insight.get("top_reasons")),
            insight.get("message"),
        )
        for insight in data.get("policy_insights") or []
    )
    if not policy_rows:
        policy_rows = html_table_row(
            "none",
            "",
            "",
            0,
            0,
            0,
            0,
            0,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        )
    context_rows = "\n".join(
        html_table_row(
            section.get("category"),
            section.get("label"),
            section.get("source_count"),
            section.get("distinct_entity_count"),
            section.get("observation_count"),
            format_narrative_entries(section.get("top_entities")),
        )
        for section in sorted(
            (data.get("context_sections") or {}).values(),
            key=lambda item: item.get("category", ""),
        )
    )
    if not context_rows:
        context_rows = html_table_row("none", "", 0, 0, 0, "")
    graph_validation_rows = html_table_row(
        "not-collected",
        "",
        0,
        0,
        0,
        "none",
        "none",
        "none",
        "false",
        "false",
        0,
    )
    if relationship_audit.get("available"):
        graph_validation_rows = html_table_row(
            "found" if relationship_audit.get("found") else "missing",
            format_audit_target_summary(relationship_audit.get("target")),
            relationship_audit.get("relationship_count", 0),
            relationship_audit.get("outbound_count", 0),
            relationship_audit.get("inbound_count", 0),
            relationship_audit.get("coverage_status", ""),
            format_text_values(relationship_audit.get("present_quadrants")),
            format_text_values(relationship_audit.get("missing_quadrants")),
            str(relationship_audit.get("kill_chain_required", False)).lower(),
            str(relationship_audit.get("kill_chain_present", False)).lower(),
            relationship_audit.get("kill_chain_attack_pattern_count", 0),
        )

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NarrowCTI curation report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #202124; }}
    h1, h2 {{ margin: 0 0 12px; }}
    section {{ margin-top: 24px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
    th, td {{ border: 1px solid #d8dee4; padding: 6px 8px; text-align: left; }}
    th {{ background: #f6f8fa; }}
    code {{ background: #f6f8fa; padding: 1px 4px; }}
  </style>
</head>
<body>
  <h1>NarrowCTI curation report</h1>
  <section>
    <h2>Snapshot</h2>
    <p><strong>schema:</strong> <code>{schema}</code></p>
    <p><strong>generated_at:</strong> <code>{generated_at}</code></p>
    <p><strong>redaction_profile:</strong> <code>{redaction_profile}</code></p>
    <p><strong>redaction_policy:</strong> <code>{redaction_policy}</code></p>
  </section>
  <section>
    <h2>Executive Summary</h2>
    <table>
      <tr><th>runs</th><th>sources</th><th>decision records</th><th>reviewed</th><th>accepted</th><th>filtered</th><th>errors</th></tr>
      <tr><td>{runs}</td><td>{sources}</td><td>{decision_records}</td><td>{reviewed}</td><td>{accepted}</td><td>{filtered}</td><td>{errors}</td></tr>
    </table>
    <table>
      <tr><th>acceptance rate</th><th>filter rate</th><th>error rate</th><th>pending review</th><th>exportable review</th><th>quarantine decisions</th></tr>
      <tr><td>{acceptance_rate_pct}</td><td>{filter_rate_pct}</td><td>{error_rate_pct}</td><td>{pending_review}</td><td>{exportable_review}</td><td>{quarantine_decisions}</td></tr>
    </table>
  </section>
  <section>
    <h2>Analyst Review Actions</h2>
    <table>
      <tr><th>events</th><th>released</th><th>rejected</th><th>exported</th><th>release rate</th><th>reject rate</th></tr>
      <tr><td>{review_actions}</td><td>{review_released}</td><td>{review_rejected}</td><td>{review_exported}</td><td>{review_release_rate_pct}</td><td>{review_reject_rate_pct}</td></tr>
    </table>
    <table>
      <tr><th>released indicators</th><th>exported indicators</th><th>dedup duplicates</th></tr>
      <tr><td>{released_indicators}</td><td>{exported_indicators}</td><td>{dedup_duplicates}</td></tr>
    </table>
  </section>
  <section>
    <h2>Graph Readiness</h2>
    <table>
      <tr><th>candidates</th><th>accepted</th><th>held</th><th>lookup matches</th><th>would-create objects</th><th>would-create relationships</th></tr>
      <tr><td>{graph_candidates}</td><td>{graph_accepted}</td><td>{graph_held}</td><td>{lookup_matches}</td><td>{would_create_objects}</td><td>{would_create_relationships}</td></tr>
    </table>
    <table>
      <tr><th>STIX bundles</th><th>STIX objects</th><th>STIX relationships</th></tr>
      <tr><td>{stix_bundles}</td><td>{stix_objects}</td><td>{stix_relationships}</td></tr>
    </table>
  </section>
  <section>
    <h2>Graph Validation</h2>
    <table>
      <tr><th>status</th><th>target</th><th>relationships</th><th>outbound</th><th>inbound</th><th>coverage</th><th>present quadrants</th><th>missing quadrants</th><th>kill chain required</th><th>kill chain present</th><th>attack patterns</th></tr>
      {graph_validation_rows}
    </table>
  </section>
  <section>
    <h2>Context Sections</h2>
    <table>
      <tr><th>category</th><th>label</th><th>sources</th><th>distinct entities</th><th>observations</th><th>top entities</th></tr>
      {context_rows}
    </table>
  </section>
  <section>
    <h2>Source Summaries</h2>
    <table>
      <tr><th>source</th><th>posture</th><th>runs</th><th>failed</th><th>reviewed</th><th>accepted</th><th>filtered</th><th>errors</th><th>decision records</th><th>pending review</th><th>released</th><th>rejected</th><th>context narrative</th></tr>
      {source_rows}
    </table>
  </section>
  <section>
    <h2>Policy Insights</h2>
    <table>
      <tr><th>source</th><th>severity</th><th>signal</th><th>review decisions</th><th>released</th><th>rejected</th><th>release rate</th><th>reject rate</th><th>scores</th><th>graph evidence</th><th>context quality</th><th>context narrative</th><th>quarantine reasons</th><th>top reasons</th><th>message</th></tr>
      {policy_rows}
    </table>
  </section>
  <section>
    <h2>Recommendations</h2>
    <ul>
      {recommendations}
    </ul>
  </section>
</body>
</html>""".format(
        schema=escape(data["schema_version"]),
        generated_at=escape(data["generated_at"]),
        redaction_profile=escape(data["redaction_profile"]),
        redaction_policy=escape(format_redaction_policy(redaction_policy)),
        runs=escape(summary["run_count"]),
        sources=escape(summary["source_count"]),
        decision_records=escape(summary["decision_record_count"]),
        reviewed=escape(summary["reviewed_count"]),
        accepted=escape(summary["accepted_count"]),
        filtered=escape(summary["filtered_count"]),
        errors=escape(summary["error_count"]),
        acceptance_rate_pct=escape(summary["acceptance_rate_pct"]),
        filter_rate_pct=escape(summary["filter_rate_pct"]),
        error_rate_pct=escape(summary["error_rate_pct"]),
        pending_review=escape(summary["pending_review_count"]),
        exportable_review=escape(summary["exportable_review_count"]),
        quarantine_decisions=escape(summary["quarantine_decision_count"]),
        review_actions=escape(summary["review_action_count"]),
        review_released=escape(summary["review_release_count"]),
        review_rejected=escape(summary["review_reject_count"]),
        review_exported=escape(summary["review_export_count"]),
        review_release_rate_pct=escape(summary["review_release_rate_pct"]),
        review_reject_rate_pct=escape(summary["review_reject_rate_pct"]),
        released_indicators=escape(review_actions.get("released_indicator_count", 0)),
        exported_indicators=escape(review_actions.get("exported_indicator_count", 0)),
        dedup_duplicates=escape(review_actions.get("dedup_duplicate_count", 0)),
        graph_candidates=escape(summary["graph_candidate_count"]),
        graph_accepted=escape(summary["graph_accepted_count"]),
        graph_held=escape(summary["graph_held_count"]),
        lookup_matches=escape(summary["graph_lookup_match_count"]),
        would_create_objects=escape(summary["graph_would_create_object_count"]),
        would_create_relationships=escape(
            summary["graph_would_create_relationship_count"]
        ),
        stix_bundles=escape(summary["graph_stix_bundle_count"]),
        stix_objects=escape(summary["graph_stix_object_count"]),
        stix_relationships=escape(summary["graph_stix_relationship_count"]),
        graph_validation_rows=graph_validation_rows,
        context_rows=context_rows,
        source_rows=source_rows,
        policy_rows=policy_rows,
        recommendations=recommendations,
    )


def write_html_report(report, html_file, redaction_profile="none"):
    html_file = str(html_file or "").strip()
    if not html_file:
        raise ValueError("html_file is required")
    directory = os.path.dirname(html_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(html_file, "w", encoding="utf-8") as handle:
        handle.write(
            format_html_report(report, redaction_profile=redaction_profile) + "\n"
        )
    return html_file


def render_report(report, output_format="text", redaction_profile="none"):
    output_format = normalize_output_format(output_format)
    if output_format == "json":
        return json.dumps(
            report_to_dict(report, redaction_profile=redaction_profile),
            sort_keys=True,
        )
    return format_text_report(report, redaction_profile=redaction_profile)


def normalize_output_format(value):
    output_format = str(value or "text").strip().lower()
    if output_format not in ("text", "json"):
        raise ValueError("output_format must be one of: text,json")
    return output_format


def write_report(report, output_file, output_format="text", redaction_profile="none"):
    output_file = str(output_file or "").strip()
    if not output_file:
        raise ValueError("output_file is required")
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(
            render_report(
                report,
                output_format=output_format,
                redaction_profile=redaction_profile,
            )
            + "\n"
        )
    return output_file


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def html_table_row(*values):
    return "<tr>{}</tr>".format(
        "".join(f"<td>{escape(value)}</td>" for value in values)
    )


def format_redaction_policy(policy):
    policy = policy or {}
    removed_fields = policy.get("removed_fields") or ["none"]
    retained_sections = policy.get("retained_sections") or ["none"]
    return (
        f"audience={policy.get('audience', '')} "
        f"raw_evidence_included="
        f"{str(policy.get('raw_evidence_included', False)).lower()} "
        f"aggregate_only={str(policy.get('aggregate_only', False)).lower()} "
        f"removed_fields={','.join(removed_fields)} "
        f"retained_sections={','.join(retained_sections)}"
    )


def format_reason_entries(entries):
    entries = list(entries or [])
    if not entries:
        return "none"
    return "; ".join(
        "{}:{}={}".format(
            entry.get("action", "review"),
            entry.get("reason", "(no reason)"),
            entry.get("count", 0),
        )
        for entry in entries
    )


def format_policy_score_summary(summary):
    summary = summary or empty_score_summary()
    bands = summary.get("bands") or {}
    low_score_count = int(bands.get("0-29", 0) or 0) + int(
        bands.get("30-49", 0) or 0
    )
    return (
        f"records={summary.get('records_with_score', 0)} "
        f"min={format_optional(summary.get('min_score'))} "
        f"max={format_optional(summary.get('max_score'))} "
        f"average={format_optional(summary.get('average_score'))} "
        f"low={low_score_count}"
    )


def format_graph_evidence_summary(summary):
    summary = summary or empty_graph_evidence_summary()
    return (
        f"candidates={summary.get('candidate_count', 0)} "
        f"density={summary.get('candidate_density', 0.0)} "
        f"accepted={summary.get('accepted_count', 0)} "
        f"held={summary.get('held_count', 0)} "
        f"lookup_matches={summary.get('lookup_match_count', 0)} "
        f"lookup_rate={summary.get('lookup_match_rate_pct', 0.0)} "
        f"would_create_objects={summary.get('would_create_object_count', 0)} "
        f"would_create_relationships="
        f"{summary.get('would_create_relationship_count', 0)} "
        f"relationship_density={summary.get('relationship_density', 0.0)} "
        f"stix_objects={summary.get('stix_object_count', 0)} "
        f"stix_relationships={summary.get('stix_relationship_count', 0)} "
        f"accepted_object_types="
        f"{format_count_entries(summary.get('top_accepted_objects'))} "
        f"accepted_relationship_types="
        f"{format_count_entries(summary.get('top_accepted_relationships'))} "
        f"lookup_object_types={format_count_entries(summary.get('top_lookup_objects'))} "
        f"stix_object_types={format_count_entries(summary.get('top_stix_objects'))} "
        f"stix_relationship_types="
        f"{format_count_entries(summary.get('top_stix_relationships'))}"
    )


def format_context_quality_summary(summary):
    summary = summary or empty_context_quality_summary()
    return (
        f"records={summary.get('record_count', 0)} "
        f"accepted_context={summary.get('accepted_candidate_count', 0)} "
        f"density={summary.get('candidate_density', 0.0)} "
        f"adjustments={summary.get('adjustment_count', 0)} "
        f"avg_delta={format_optional(summary.get('average_score_delta'))} "
        f"max_contextual_score="
        f"{format_optional(summary.get('max_contextual_score'))} "
        f"categories={format_category_entries(summary.get('top_categories'))}"
    )


def format_context_narrative_summary(summary):
    summary = summary or empty_context_narrative_summary()
    return (
        f"records={summary.get('record_count', 0)} "
        f"entities={summary.get('entity_count', 0)} "
        f"attack_patterns="
        f"{format_narrative_entries(summary.get('top_attack_patterns'))} "
        f"arsenal={format_narrative_entries(summary.get('top_arsenal'))} "
        f"infrastructure="
        f"{format_narrative_entries(summary.get('top_infrastructure'))} "
        f"threats={format_narrative_entries(summary.get('top_threat_actors'))} "
        f"sectors={format_narrative_entries(summary.get('top_target_sectors'))} "
        f"overlaps={format_mapping_counts(summary.get('overlap_counts'))}"
    )


def format_audit_target_summary(target):
    target = target or {}
    entity_type = target.get("entity_type") or "object"
    name = (
        target.get("name")
        or target.get("observable_value")
        or target.get("standard_id")
        or target.get("id")
        or ""
    )
    if not name:
        return str(entity_type)
    return f"{entity_type}:{name}"


def format_text_values(values):
    values = [str(value) for value in values or [] if str(value or "").strip()]
    if not values:
        return "none"
    return ",".join(values)


def format_context_section_summary(section):
    section = section or {}
    return (
        f"label={section.get('label', '')} "
        f"sources={section.get('source_count', 0)} "
        f"distinct_entities={section.get('distinct_entity_count', 0)} "
        f"observations={section.get('observation_count', 0)} "
        f"shared_entities={section.get('shared_entity_count', 0)} "
        f"top={format_narrative_entries(section.get('top_entities'))}"
    )


def format_mapping_counts(counts):
    counts = counts or {}
    if not counts:
        return "none"
    return ",".join(f"{key}:{counts.get(key, 0)}" for key in sorted(counts))


def format_category_entries(entries):
    entries = list(entries or [])
    if not entries:
        return "none"
    return ",".join(
        "{}:{}".format(
            entry.get("category", "unknown"),
            entry.get("count", 0),
        )
        for entry in entries
    )


def format_narrative_entries(entries):
    entries = list(entries or [])
    if not entries:
        return "none"
    return ",".join(
        "{}:{}".format(
            entry.get("display_name") or entry.get("value") or "unknown",
            entry.get("count", 0),
        )
        for entry in entries
    )


def format_count_entries(entries):
    entries = list(entries or [])
    if not entries:
        return "none"
    return ",".join(
        "{}:{}".format(
            entry.get("type", "unknown"),
            entry.get("count", 0),
        )
        for entry in entries
    )


def format_optional(value):
    return "none" if value is None else value


def main():
    parser = argparse.ArgumentParser(
        description="Build an analyst-facing NarrowCTI curation report."
    )
    parser.add_argument(
        "--summary-file",
        default="",
        help="Gateway run summary JSONL. Defaults to NARROWCTI_RUN_SUMMARY_FILE.",
    )
    parser.add_argument(
        "--decision-path",
        action="append",
        default=[],
        help="Decision audit JSONL file or directory. Can be passed more than once.",
    )
    parser.add_argument(
        "--quarantine-file",
        default="",
        help="Quarantine repository JSONL. Defaults to NARROWCTI_QUARANTINE_REPOSITORY.",
    )
    parser.add_argument(
        "--release-audit-file",
        default="",
        help="Release audit JSONL. Defaults to NARROWCTI_RELEASE_AUDIT_FILE.",
    )
    parser.add_argument(
        "--relationship-audit-file",
        default=os.getenv("NARROWCTI_OPENCTI_RELATIONSHIP_AUDIT_FILE", ""),
        help="Optional JSON file produced by gateway.opencti_relationship_audit.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Read only the most recent N records where supported.",
    )
    parser.add_argument(
        "--html-file",
        default="",
        help="Optional HTML report output file.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional text report output file.",
    )
    parser.add_argument(
        "--json-file",
        default="",
        help="Optional JSON report output file.",
    )
    parser.add_argument(
        "--redaction-profile",
        choices=REDACTION_PROFILES,
        default="none",
        help="Redact detailed local evidence for support sharing.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    settings = load_settings()
    report = build_curation_report_from_files(
        summary_file=args.summary_file or settings.run_summary_file,
        decision_paths=args.decision_path or [settings.decision_audit_dir],
        quarantine_file=args.quarantine_file or settings.quarantine_repository_file,
        release_audit_file=args.release_audit_file or settings.release_audit_file,
        relationship_audit_file=args.relationship_audit_file,
        limit=args.limit,
    )
    if args.html_file:
        write_html_report(
            report,
            args.html_file,
            redaction_profile=args.redaction_profile,
        )
    if args.output_file:
        write_report(
            report,
            args.output_file,
            output_format="text",
            redaction_profile=args.redaction_profile,
        )
    if args.json_file:
        write_report(
            report,
            args.json_file,
            output_format="json",
            redaction_profile=args.redaction_profile,
        )
    if args.json:
        print(render_report(report, "json", redaction_profile=args.redaction_profile))
    else:
        print(render_report(report, "text", redaction_profile=args.redaction_profile))


if __name__ == "__main__":
    main()
