import argparse
import glob
import json
import os
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from gateway.settings import load_settings


ACTION_ORDER = (
    "ingest",
    "drop",
    "quarantine",
    "skip",
    "dry-run",
    "error",
)

GRAPH_ENTITY_CATEGORIES = {
    "attack_pattern": "attack_patterns",
    "threat_actor": "threat_actors",
    "intrusion_set": "threat_actors",
    "target_sector": "target_sectors",
}

GRAPH_ENTITY_TOP_FIELDS = {
    "attack_patterns": "top_attack_patterns",
    "threat_actors": "top_threat_actors",
    "target_sectors": "top_target_sectors",
}


@dataclass(frozen=True)
class DecisionAuditReport:
    record_count: int
    first_recorded_at: str
    last_recorded_at: str
    actions: dict
    reasons: list
    quarantined: list
    queries: list
    score_summary: dict
    graph_export: dict
    contextual_scoring: dict
    graph_stix_preview: dict
    graph_entities: dict
    sources: dict

    def to_dict(self):
        return {
            "record_count": self.record_count,
            "first_recorded_at": self.first_recorded_at,
            "last_recorded_at": self.last_recorded_at,
            "actions": self.actions,
            "reasons": self.reasons,
            "quarantined": self.quarantined,
            "queries": self.queries,
            "score_summary": self.score_summary,
            "graph_export": self.graph_export,
            "contextual_scoring": self.contextual_scoring,
            "graph_stix_preview": self.graph_stix_preview,
            "graph_entities": self.graph_entities,
            "sources": self.sources,
        }


def read_decision_records(paths, limit=None):
    records = []
    for path in expand_paths(paths):
        with open(path, "r", encoding="utf-8") as file_obj:
            for line in file_obj:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))
    records.sort(key=lambda record: record.get("recorded_at", ""))
    if limit is not None and limit > 0:
        records = records[-limit:]
    return records


def expand_paths(paths):
    expanded = []
    for path in paths or ():
        if os.path.isdir(path):
            expanded.extend(sorted(glob.glob(os.path.join(path, "*.jsonl"))))
        elif not os.path.exists(path) and os.path.splitext(path)[1].lower() != ".jsonl":
            continue
        else:
            expanded.append(path)
    return expanded


def build_decision_audit_report(records, reason_limit=10, quarantine_limit=10):
    if not records:
        return DecisionAuditReport(
            record_count=0,
            first_recorded_at="",
            last_recorded_at="",
            actions=empty_actions(),
            reasons=[],
            quarantined=[],
            queries=[],
            score_summary={
                "overall": build_score_summary([]),
                "by_action": {},
            },
            graph_export=build_graph_export_summary([]),
            contextual_scoring=build_contextual_scoring_summary([]),
            graph_stix_preview=build_graph_stix_preview_summary([]),
            graph_entities=build_graph_entity_summary([]),
            sources={},
        )

    actions = empty_actions()
    reason_counts = Counter()
    sources = {}
    queries = {}
    records_by_action = {}
    records_by_source = {}

    for record in records:
        action = normalize_action(record.get("action"), "unknown")
        reason = normalize_value(record.get("reason"), "unspecified")
        source_key = normalize_value(record.get("source_key"), "unknown")
        query = normalize_value(record.get("query"), "(none)")

        actions[action] = actions.get(action, 0) + 1
        reason_counts[(action, reason)] += 1
        records_by_action.setdefault(action, []).append(record)
        records_by_source.setdefault(source_key, []).append(record)

        source_report = sources.setdefault(
            source_key,
            {
                "records": 0,
                "actions": empty_actions(),
                "reasons": {},
                "action_reasons": {},
                "score_summary": {},
            },
        )
        source_report["records"] += 1
        source_report["actions"][action] = source_report["actions"].get(action, 0) + 1
        source_report["reasons"][reason] = source_report["reasons"].get(reason, 0) + 1
        source_action_reasons = source_report["action_reasons"].setdefault(action, {})
        source_action_reasons[reason] = source_action_reasons.get(reason, 0) + 1
        query_report = queries.setdefault(
            (source_key, query),
            {
                "source_key": source_key,
                "query": query,
                "records": 0,
                "actions": empty_actions(),
                "reasons": {},
                "score_summary": {},
                "_records": [],
            },
        )
        query_report["records"] += 1
        query_report["actions"][action] = query_report["actions"].get(action, 0) + 1
        query_report["reasons"][reason] = query_report["reasons"].get(reason, 0) + 1
        query_report["_records"].append(record)

    for source_key, source_records in records_by_source.items():
        sources[source_key]["score_summary"] = build_score_summary(source_records)
        sources[source_key]["action_reasons"] = {
            action: dict(sorted(reasons.items()))
            for action, reasons in sorted(
                (sources[source_key].get("action_reasons") or {}).items()
            )
        }

    return DecisionAuditReport(
        record_count=len(records),
        first_recorded_at=records[0].get("recorded_at", ""),
        last_recorded_at=records[-1].get("recorded_at", ""),
        actions=actions,
        reasons=top_reasons(reason_counts, reason_limit),
        quarantined=quarantine_candidates(records, quarantine_limit),
        queries=sorted_query_reports(queries),
        score_summary={
            "overall": build_score_summary(records),
            "by_action": {
                action: build_score_summary(action_records)
                for action, action_records in sorted(records_by_action.items())
            },
        },
        graph_export=build_graph_export_summary(records),
        contextual_scoring=build_contextual_scoring_summary(records),
        graph_stix_preview=build_graph_stix_preview_summary(records),
        graph_entities=build_graph_entity_summary(records),
        sources=sources,
    )


def sorted_query_reports(queries):
    reports = []
    for query_report in queries.values():
        records = query_report.pop("_records", [])
        query_report["score_summary"] = build_score_summary(records)
        reports.append(query_report)
    return sorted(
        reports,
        key=lambda item: (
            -int(item.get("records", 0) or 0),
            item.get("source_key", ""),
            item.get("query", ""),
        ),
    )


def empty_actions():
    return {action: 0 for action in ACTION_ORDER}


def normalize_value(value, default):
    value = str(value or "").strip()
    return value or default


def normalize_action(value, default):
    action = normalize_value(value, default)
    aliases = {
        "dry_run": "dry-run",
    }
    return aliases.get(action, action)


def top_reasons(reason_counts, limit):
    items = sorted(
        reason_counts.items(),
        key=lambda item: (-item[1], item[0][0], item[0][1]),
    )
    if limit and limit > 0:
        items = items[:limit]
    return [
        {"action": action, "reason": reason, "count": count}
        for (action, reason), count in items
    ]


def quarantine_candidates(records, limit):
    candidates = [
        quarantine_record(record)
        for record in records or ()
        if normalize_value(record.get("action"), "") == "quarantine"
    ]
    candidates.sort(
        key=lambda item: (
            item.get("recorded_at", ""),
            item.get("source_key", ""),
            item.get("external_id", ""),
        ),
        reverse=True,
    )
    if limit and limit > 0:
        candidates = candidates[:limit]
    return candidates


def quarantine_record(record):
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        metadata = {}
    return {
        "recorded_at": normalize_value(record.get("recorded_at"), ""),
        "source_key": normalize_value(record.get("source_key"), "unknown"),
        "external_id": normalize_value(record.get("external_id"), ""),
        "title": normalize_value(record.get("title"), "(untitled)"),
        "query": normalize_value(record.get("query"), ""),
        "reason": normalize_value(record.get("reason"), "unspecified"),
        "score": coerce_score(record.get("score")),
        "age_days": record.get("age_days"),
        "indicator_count": int(record.get("indicator_count", 0) or 0),
        "metadata": dict(metadata),
    }


def build_graph_export_summary(records):
    summary = empty_graph_export_summary()
    by_source = {}
    by_query = {}

    for record in records or ():
        plan = graph_export_plan(record)
        if not plan:
            continue
        source_key = normalize_value(record.get("source_key"), "unknown")
        query = normalize_value(record.get("query"), "(none)")
        lookup_matches = graph_lookup_matches(record)
        merge_graph_export_plan(summary, plan, lookup_matches)
        merge_graph_export_plan(
            by_source.setdefault(source_key, empty_graph_export_summary(False)),
            plan,
            lookup_matches,
        )
        merge_graph_export_plan(
            by_query.setdefault(
                (source_key, query),
                {
                    "source_key": source_key,
                    "query": query,
                    **empty_graph_export_summary(False),
                },
            ),
            plan,
            lookup_matches,
        )

    summary["modes"] = dict(sorted(summary["modes"].items()))
    summary["statuses"] = dict(sorted(summary["statuses"].items()))
    summary["actions"] = dict(sorted(summary["actions"].items()))
    summary["held_reasons"] = dict(sorted(summary["held_reasons"].items()))
    summary["accepted_object_counts"] = dict(
        sorted(summary["accepted_object_counts"].items())
    )
    summary["accepted_relationship_counts"] = dict(
        sorted(summary["accepted_relationship_counts"].items())
    )
    summary["lookup_match_object_counts"] = dict(
        sorted(summary["lookup_match_object_counts"].items())
    )
    summary["lookup_match_type_counts"] = dict(
        sorted(summary["lookup_match_type_counts"].items())
    )
    summary["lookup_canonical_entity_counts"] = dict(
        sorted(summary["lookup_canonical_entity_counts"].items())
    )
    summary["by_source"] = {
        source: normalize_graph_export_summary(source_summary)
        for source, source_summary in sorted(by_source.items())
    }
    summary["by_query"] = [
        normalize_graph_export_summary(query_summary)
        for _, query_summary in sorted(
            by_query.items(),
            key=lambda item: (
                -int(item[1].get("record_count", 0) or 0),
                item[1].get("source_key", ""),
                item[1].get("query", ""),
            ),
        )
    ]
    return summary


def empty_graph_export_summary(include_breakdowns=True):
    summary = {
        "record_count": 0,
        "candidate_count": 0,
        "accepted_count": 0,
        "held_count": 0,
        "deduplicated_candidate_count": 0,
        "deduplicated_entity_count": 0,
        "deduplicated_relationship_count": 0,
        "would_create_object_count": 0,
        "would_create_relationship_count": 0,
        "modes": {},
        "statuses": {},
        "actions": {},
        "held_reasons": {},
        "accepted_object_counts": {},
        "accepted_relationship_counts": {},
        "lookup_match_count": 0,
        "lookup_match_object_counts": {},
        "lookup_match_type_counts": {},
        "lookup_canonical_entity_counts": {},
    }
    if include_breakdowns:
        summary["by_source"] = {}
        summary["by_query"] = []
    return summary


def normalize_graph_export_summary(summary):
    for field in (
        "modes",
        "statuses",
        "actions",
        "held_reasons",
        "accepted_object_counts",
        "accepted_relationship_counts",
        "lookup_match_object_counts",
        "lookup_match_type_counts",
        "lookup_canonical_entity_counts",
    ):
        summary[field] = dict(sorted(summary.get(field, {}).items()))
    return summary


def graph_export_plan(record):
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return {}
    plan = metadata.get("graph_export_plan")
    return dict(plan) if isinstance(plan, Mapping) else {}


def graph_lookup_matches(record):
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return []
    matches = metadata.get("graph_export_plan_lookup_matches")
    return [dict(match) for match in matches or [] if isinstance(match, Mapping)]


def merge_graph_export_plan(summary, plan, lookup_matches=None):
    summary["record_count"] += 1
    summary["candidate_count"] += int(plan.get("candidate_count", 0) or 0)
    summary["accepted_count"] += int(plan.get("accepted_count", 0) or 0)
    summary["held_count"] += int(plan.get("held_count", 0) or 0)
    summary["deduplicated_candidate_count"] += int(
        plan.get("deduplicated_candidate_count", 0) or 0
    )
    summary["deduplicated_entity_count"] += int(
        plan.get("deduplicated_entity_count", 0) or 0
    )
    summary["deduplicated_relationship_count"] += int(
        plan.get("deduplicated_relationship_count", 0) or 0
    )
    summary["would_create_object_count"] += int(
        plan.get("would_create_object_count", 0) or 0
    )
    summary["would_create_relationship_count"] += int(
        plan.get("would_create_relationship_count", 0) or 0
    )
    increment_count(summary["modes"], normalize_value(plan.get("mode"), "unknown"))
    increment_count(summary["statuses"], normalize_value(plan.get("status"), "unknown"))
    merge_counts(summary["held_reasons"], plan.get("held_reasons"))
    merge_counts(summary["accepted_object_counts"], plan.get("accepted_object_counts"))
    merge_counts(
        summary["accepted_relationship_counts"],
        plan.get("accepted_relationship_counts"),
    )
    lookup_matches = lookup_matches or []
    summary["lookup_match_count"] += len(lookup_matches)
    for match in lookup_matches:
        increment_count(
            summary["lookup_match_object_counts"],
            normalize_value(match.get("stix_object_type"), "unknown"),
        )
        canonical = match.get("match")
        if isinstance(canonical, Mapping):
            increment_count(
                summary["lookup_match_type_counts"],
                normalize_value(canonical.get("match_type"), "unknown"),
            )
            increment_count(
                summary["lookup_canonical_entity_counts"],
                normalize_value(canonical.get("entity_type"), "unknown"),
            )
    for action in plan.get("actions") or []:
        if isinstance(action, Mapping):
            increment_count(
                summary["actions"],
                normalize_value(action.get("action"), "unknown"),
            )


def build_contextual_scoring_summary(records):
    summary = empty_contextual_scoring_summary()
    by_source = {}
    by_query = {}

    for record in records or ():
        scoring = contextual_scoring(record)
        if not scoring:
            continue
        source_key = normalize_value(record.get("source_key"), "unknown")
        query = normalize_value(record.get("query"), "(none)")
        merge_contextual_scoring(summary, scoring)
        merge_contextual_scoring(
            by_source.setdefault(source_key, empty_contextual_scoring_summary(False)),
            scoring,
        )
        merge_contextual_scoring(
            by_query.setdefault(
                (source_key, query),
                {
                    "source_key": source_key,
                    "query": query,
                    **empty_contextual_scoring_summary(False),
                },
            ),
            scoring,
        )

    normalize_contextual_scoring_summary(summary)
    summary["by_source"] = {
        source: normalize_contextual_scoring_summary(source_summary)
        for source, source_summary in sorted(by_source.items())
    }
    summary["by_query"] = [
        normalize_contextual_scoring_summary(query_summary)
        for _, query_summary in sorted(
            by_query.items(),
            key=lambda item: (
                -int(item[1].get("record_count", 0) or 0),
                item[1].get("source_key", ""),
                item[1].get("query", ""),
            ),
        )
    ]
    return summary


def empty_contextual_scoring_summary(include_breakdowns=True):
    summary = {
        "record_count": 0,
        "accepted_candidate_count": 0,
        "adjustment_count": 0,
        "score_delta_total": 0,
        "average_score_delta": None,
        "max_contextual_score": None,
        "capped_count": 0,
        "applied_to_decision_count": 0,
        "modes": {},
        "statuses": {},
        "category_counts": {},
    }
    if include_breakdowns:
        summary["by_source"] = {}
        summary["by_query"] = []
    return summary


def normalize_contextual_scoring_summary(summary):
    if summary.get("record_count"):
        summary["average_score_delta"] = round(
            summary.get("score_delta_total", 0) / summary["record_count"],
            2,
        )
    for field in ("modes", "statuses", "category_counts"):
        summary[field] = dict(sorted(summary.get(field, {}).items()))
    return summary


def contextual_scoring(record):
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return {}
    scoring = metadata.get("contextual_scoring")
    return dict(scoring) if isinstance(scoring, Mapping) else {}


def merge_contextual_scoring(summary, scoring):
    summary["record_count"] += 1
    summary["accepted_candidate_count"] += int(
        scoring.get("accepted_candidate_count", 0) or 0
    )
    summary["adjustment_count"] += int(scoring.get("adjustment_count", 0) or 0)
    summary["score_delta_total"] += int(scoring.get("score_delta", 0) or 0)
    contextual_score = coerce_score(scoring.get("contextual_score"))
    if contextual_score is not None:
        current = summary.get("max_contextual_score")
        summary["max_contextual_score"] = (
            contextual_score if current is None else max(current, contextual_score)
        )
    if scoring.get("capped"):
        summary["capped_count"] += 1
    if scoring.get("applied_to_decision"):
        summary["applied_to_decision_count"] += 1
    increment_count(summary["modes"], normalize_value(scoring.get("mode"), "unknown"))
    increment_count(
        summary["statuses"],
        normalize_value(scoring.get("status"), "unknown"),
    )
    merge_counts(summary["category_counts"], scoring.get("category_counts"))


def build_graph_stix_preview_summary(records):
    summary = empty_graph_stix_preview_summary()
    by_source = {}
    by_query = {}

    for record in records or ():
        preview = graph_stix_preview(record)
        if not preview:
            continue
        source_key = normalize_value(record.get("source_key"), "unknown")
        query = normalize_value(record.get("query"), "(none)")
        merge_graph_stix_preview(summary, preview)
        merge_graph_stix_preview(
            by_source.setdefault(source_key, empty_graph_stix_preview_summary(False)),
            preview,
        )
        merge_graph_stix_preview(
            by_query.setdefault(
                (source_key, query),
                {
                    "source_key": source_key,
                    "query": query,
                    **empty_graph_stix_preview_summary(False),
                },
            ),
            preview,
        )

    normalize_graph_stix_preview_summary(summary)
    summary["by_source"] = {
        source: normalize_graph_stix_preview_summary(source_summary)
        for source, source_summary in sorted(by_source.items())
    }
    summary["by_query"] = [
        normalize_graph_stix_preview_summary(query_summary)
        for _, query_summary in sorted(
            by_query.items(),
            key=lambda item: (
                -int(item[1].get("record_count", 0) or 0),
                item[1].get("source_key", ""),
                item[1].get("query", ""),
            ),
        )
    ]
    return summary


def empty_graph_stix_preview_summary(include_breakdowns=True):
    summary = {
        "record_count": 0,
        "accepted_candidate_count": 0,
        "bundle_object_count": 0,
        "graph_object_count": 0,
        "graph_relationship_count": 0,
        "semantic_relationship_count": 0,
        "report_relationship_count": 0,
        "skipped_candidate_count": 0,
        "export_enabled_count": 0,
        "statuses": {},
        "bundle_types": {},
        "object_counts": {},
        "relationship_counts": {},
        "proposed_relationship_counts": {},
    }
    if include_breakdowns:
        summary["by_source"] = {}
        summary["by_query"] = []
    return summary


def normalize_graph_stix_preview_summary(summary):
    for field in (
        "statuses",
        "bundle_types",
        "object_counts",
        "relationship_counts",
        "proposed_relationship_counts",
    ):
        summary[field] = dict(sorted(summary.get(field, {}).items()))
    return summary


def graph_stix_preview(record):
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return {}
    preview = metadata.get("graph_stix_preview")
    return dict(preview) if isinstance(preview, Mapping) else {}


def merge_graph_stix_preview(summary, preview):
    summary["record_count"] += 1
    summary["accepted_candidate_count"] += int(
        preview.get("accepted_candidate_count", 0) or 0
    )
    summary["bundle_object_count"] += int(preview.get("bundle_object_count", 0) or 0)
    summary["graph_object_count"] += int(preview.get("graph_object_count", 0) or 0)
    summary["graph_relationship_count"] += int(
        preview.get("graph_relationship_count", 0) or 0
    )
    summary["semantic_relationship_count"] += int(
        preview.get("semantic_relationship_count", 0) or 0
    )
    summary["report_relationship_count"] += int(
        preview.get("report_relationship_count", 0) or 0
    )
    summary["skipped_candidate_count"] += int(
        preview.get("skipped_candidate_count", 0) or 0
    )
    if preview.get("export_enabled"):
        summary["export_enabled_count"] += 1
    increment_count(summary["statuses"], normalize_value(preview.get("status"), "unknown"))
    increment_count(
        summary["bundle_types"],
        normalize_value(preview.get("bundle_type"), "unknown"),
    )
    merge_counts(summary["object_counts"], preview.get("object_counts"))
    merge_counts(summary["relationship_counts"], preview.get("relationship_counts"))
    merge_counts(
        summary["proposed_relationship_counts"],
        preview.get("proposed_relationship_counts"),
    )


def build_graph_entity_summary(records):
    summary = empty_graph_entity_summary()
    by_source = {}
    by_query = {}

    for record in records or ():
        entities = graph_entity_entries(record)
        if not entities:
            continue
        source_key = normalize_value(record.get("source_key"), "unknown")
        query = normalize_value(record.get("query"), "(none)")
        merge_graph_entity_entries(summary, entities)
        merge_graph_entity_entries(
            by_source.setdefault(source_key, empty_graph_entity_summary(False)),
            entities,
        )
        merge_graph_entity_entries(
            by_query.setdefault(
                (source_key, query),
                {
                    "source_key": source_key,
                    "query": query,
                    **empty_graph_entity_summary(False),
                },
            ),
            entities,
        )

    normalize_graph_entity_summary(summary)
    summary["by_source"] = {
        source: normalize_graph_entity_summary(source_summary)
        for source, source_summary in sorted(by_source.items())
    }
    summary["by_query"] = [
        normalize_graph_entity_summary(query_summary)
        for _, query_summary in sorted(
            by_query.items(),
            key=lambda item: (
                -int(item[1].get("record_count", 0) or 0),
                item[1].get("source_key", ""),
                item[1].get("query", ""),
            ),
        )
    ]
    return summary


def empty_graph_entity_summary(include_breakdowns=True):
    summary = {
        "record_count": 0,
        "entity_count": 0,
        "counts": {
            "attack_patterns": 0,
            "threat_actors": 0,
            "target_sectors": 0,
        },
        "top_attack_patterns": [],
        "top_threat_actors": [],
        "top_target_sectors": [],
        "_entities": Counter(),
    }
    if include_breakdowns:
        summary["by_source"] = {}
        summary["by_query"] = []
    return summary


def graph_entity_entries(record):
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return []
    evidence = metadata.get("graph_evidence")
    if not isinstance(evidence, Mapping):
        return []
    entries = []
    for item in evidence.get("records") or ():
        if not isinstance(item, Mapping):
            continue
        entry = graph_entity_entry(item)
        if entry:
            entries.append(entry)
    return entries


def graph_entity_entry(item):
    entity_type = normalize_value(item.get("entity_type"), "")
    category = GRAPH_ENTITY_CATEGORIES.get(entity_type)
    if not category:
        return {}
    value = normalize_value(item.get("value"), "")
    display_name = normalize_value(item.get("display_name"), value)
    if not value and not display_name:
        return {}
    return {
        "category": category,
        "entity_type": entity_type,
        "value": value or display_name,
        "display_name": display_name or value,
    }


def merge_graph_entity_entries(summary, entries):
    summary["record_count"] += 1
    for entry in entries:
        category = entry["category"]
        summary["entity_count"] += 1
        summary["counts"][category] = int(summary["counts"].get(category, 0) or 0) + 1
        summary["_entities"][
            (
                category,
                entry["entity_type"],
                entry["value"],
                entry["display_name"],
            )
        ] += 1


def normalize_graph_entity_summary(summary):
    summary["counts"] = dict(sorted((summary.get("counts") or {}).items()))
    counters = summary.pop("_entities", Counter())
    for category, field_name in GRAPH_ENTITY_TOP_FIELDS.items():
        summary[field_name] = top_graph_entity_entries(counters, category)
    return summary


def top_graph_entity_entries(counter, category, limit=5):
    items = [
        (key, count)
        for key, count in (counter or {}).items()
        if key[0] == category and int(count or 0) > 0
    ]
    items.sort(key=lambda item: (-item[1], item[0][3], item[0][2], item[0][1]))
    return [
        {
            "entity_type": entity_type,
            "value": value,
            "display_name": display_name,
            "count": count,
        }
        for (_, entity_type, value, display_name), count in items[:limit]
    ]


def merge_counts(target, counts):
    if not isinstance(counts, Mapping):
        return
    for key, value in counts.items():
        target[normalize_value(key, "unknown")] = target.get(
            normalize_value(key, "unknown"),
            0,
        ) + int(value or 0)


def increment_count(target, key):
    target[key] = target.get(key, 0) + 1


def build_score_summary(records):
    scores = [
        score
        for score in (coerce_score(record.get("score")) for record in records or ())
        if score is not None
    ]
    return {
        "records_with_score": len(scores),
        "min_score": min(scores) if scores else None,
        "max_score": max(scores) if scores else None,
        "average_score": round(sum(scores) / len(scores), 2) if scores else None,
        "bands": score_bands(scores),
    }


def coerce_score(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def score_bands(scores):
    bands = {
        "0-29": 0,
        "30-49": 0,
        "50-69": 0,
        "70-89": 0,
        "90-100": 0,
    }
    for score in scores:
        if score < 30:
            bands["0-29"] += 1
        elif score < 50:
            bands["30-49"] += 1
        elif score < 70:
            bands["50-69"] += 1
        elif score < 90:
            bands["70-89"] += 1
        else:
            bands["90-100"] += 1
    return bands


def format_text_report(report):
    lines = [
        "NarrowCTI decision audit report",
        f"record_count={report.record_count}",
        f"first_recorded_at={report.first_recorded_at or '(none)'}",
        f"last_recorded_at={report.last_recorded_at or '(none)'}",
        "actions=" + format_counts(report.actions),
        "scores=" + format_score_summary(report.score_summary["overall"]),
    ]
    if report.reasons:
        lines.append("top_reasons:")
        for item in report.reasons:
            lines.append(
                f"- action={item['action']} count={item['count']} "
                f"reason={item['reason']}"
            )
    if report.graph_export.get("record_count", 0):
        graph = report.graph_export
        lines.append("graph_export:")
        lines.append("- " + format_graph_export_summary(graph))
        if graph.get("by_source"):
            lines.append("graph_export_by_source:")
            for source_key, source in graph["by_source"].items():
                lines.append(f"- source={source_key} {format_graph_export_summary(source)}")
        if graph.get("by_query"):
            lines.append("graph_export_by_query:")
            for query in graph["by_query"]:
                lines.append(
                    f"- {query['source_key']} query={query['query']} "
                    f"{format_graph_export_summary(query)}"
                )
    if report.contextual_scoring.get("record_count", 0):
        contextual = report.contextual_scoring
        lines.append("contextual_scoring:")
        lines.append("- " + format_contextual_scoring_summary(contextual))
        if contextual.get("by_source"):
            lines.append("contextual_scoring_by_source:")
            for source_key, source in contextual["by_source"].items():
                lines.append(
                    f"- source={source_key} "
                    f"{format_contextual_scoring_summary(source)}"
                )
        if contextual.get("by_query"):
            lines.append("contextual_scoring_by_query:")
            for query in contextual["by_query"]:
                lines.append(
                    f"- {query['source_key']} query={query['query']} "
                    f"{format_contextual_scoring_summary(query)}"
                )
    if report.graph_stix_preview.get("record_count", 0):
        preview = report.graph_stix_preview
        lines.append("graph_stix_preview:")
        lines.append("- " + format_graph_stix_preview_summary(preview))
        if preview.get("by_source"):
            lines.append("graph_stix_preview_by_source:")
            for source_key, source in preview["by_source"].items():
                lines.append(
                    f"- source={source_key} "
                    f"{format_graph_stix_preview_summary(source)}"
                )
        if preview.get("by_query"):
            lines.append("graph_stix_preview_by_query:")
            for query in preview["by_query"]:
                lines.append(
                    f"- {query['source_key']} query={query['query']} "
                    f"{format_graph_stix_preview_summary(query)}"
                )
    if report.graph_entities.get("record_count", 0):
        entities = report.graph_entities
        lines.append("graph_entities:")
        lines.append("- " + format_graph_entity_summary(entities))
        if entities.get("by_source"):
            lines.append("graph_entities_by_source:")
            for source_key, source in entities["by_source"].items():
                lines.append(
                    f"- source={source_key} "
                    f"{format_graph_entity_summary(source)}"
                )
        if entities.get("by_query"):
            lines.append("graph_entities_by_query:")
            for query in entities["by_query"]:
                lines.append(
                    f"- {query['source_key']} query={query['query']} "
                    f"{format_graph_entity_summary(query)}"
                )
    if report.quarantined:
        lines.append("quarantine_candidates:")
        for item in report.quarantined:
            lines.append(
                f"- {item['recorded_at'] or '(unknown-time)'} "
                f"{item['source_key']} external_id={item['external_id'] or '(none)'} "
                f"score={format_optional(item['score'])} "
                f"age_days={format_optional(item['age_days'])} "
                f"indicators={item['indicator_count']} reason={item['reason']} "
                f"title={item['title']}"
            )
    if report.queries:
        lines.append("queries:")
        for query in report.queries:
            lines.append(
                f"- {query['source_key']} query={query['query']} "
                f"records={query['records']} actions={format_counts(query['actions'])} "
                f"scores={format_score_summary(query['score_summary'])}"
            )
    if report.sources:
        lines.append("sources:")
        for source_key in sorted(report.sources):
            source = report.sources[source_key]
            lines.append(
                f"- {source_key} records={source['records']} "
                f"actions={format_counts(source['actions'])} "
                f"scores={format_score_summary(source['score_summary'])}"
            )
    return "\n".join(lines)


def format_counts(counts):
    ordered_keys = list(ACTION_ORDER) + sorted(
        key for key in counts if key not in ACTION_ORDER
    )
    return " ".join(f"{key}={counts.get(key, 0)}" for key in ordered_keys)


def format_score_summary(summary):
    bands = summary.get("bands", {})
    band_text = ",".join(f"{key}:{bands.get(key, 0)}" for key in sorted(bands))
    return (
        f"records_with_score={summary.get('records_with_score', 0)} "
        f"min_score={format_optional(summary.get('min_score'))} "
        f"max_score={format_optional(summary.get('max_score'))} "
        f"average_score={format_optional(summary.get('average_score'))} "
        f"bands={band_text}"
    )


def format_graph_export_summary(summary):
    return (
        f"records={summary.get('record_count', 0)} "
        f"candidates={summary.get('candidate_count', 0)} "
        f"accepted={summary.get('accepted_count', 0)} "
        f"held={summary.get('held_count', 0)} "
        f"deduplicated={summary.get('deduplicated_candidate_count', 0)} "
        f"deduplicated_entities={summary.get('deduplicated_entity_count', 0)} "
        f"deduplicated_relationships="
        f"{summary.get('deduplicated_relationship_count', 0)} "
        f"would_create_objects={summary.get('would_create_object_count', 0)} "
        f"would_create_relationships="
        f"{summary.get('would_create_relationship_count', 0)} "
        f"lookup_matches={summary.get('lookup_match_count', 0)} "
        f"modes={format_compact_counts(summary.get('modes', {}))} "
        f"statuses={format_compact_counts(summary.get('statuses', {}))} "
        f"actions={format_compact_counts(summary.get('actions', {}))} "
        f"held_reasons={format_compact_counts(summary.get('held_reasons', {}))} "
        f"lookup_objects="
        f"{format_compact_counts(summary.get('lookup_match_object_counts', {}))} "
        f"lookup_match_types="
        f"{format_compact_counts(summary.get('lookup_match_type_counts', {}))}"
    )


def format_contextual_scoring_summary(summary):
    return (
        f"records={summary.get('record_count', 0)} "
        f"accepted_candidates={summary.get('accepted_candidate_count', 0)} "
        f"adjustments={summary.get('adjustment_count', 0)} "
        f"score_delta_total={summary.get('score_delta_total', 0)} "
        f"average_score_delta="
        f"{format_optional(summary.get('average_score_delta'))} "
        f"max_contextual_score="
        f"{format_optional(summary.get('max_contextual_score'))} "
        f"capped={summary.get('capped_count', 0)} "
        f"applied_to_decision={summary.get('applied_to_decision_count', 0)} "
        f"modes={format_compact_counts(summary.get('modes', {}))} "
        f"statuses={format_compact_counts(summary.get('statuses', {}))} "
        f"categories={format_compact_counts(summary.get('category_counts', {}))}"
    )


def format_graph_stix_preview_summary(summary):
    return (
        f"records={summary.get('record_count', 0)} "
        f"accepted_candidates={summary.get('accepted_candidate_count', 0)} "
        f"bundle_objects={summary.get('bundle_object_count', 0)} "
        f"graph_objects={summary.get('graph_object_count', 0)} "
        f"graph_relationships={summary.get('graph_relationship_count', 0)} "
        f"semantic_relationships={summary.get('semantic_relationship_count', 0)} "
        f"report_relationships={summary.get('report_relationship_count', 0)} "
        f"skipped_candidates={summary.get('skipped_candidate_count', 0)} "
        f"export_enabled={summary.get('export_enabled_count', 0)} "
        f"statuses={format_compact_counts(summary.get('statuses', {}))} "
        f"bundle_types={format_compact_counts(summary.get('bundle_types', {}))} "
        f"objects={format_compact_counts(summary.get('object_counts', {}))} "
        f"relationships="
        f"{format_compact_counts(summary.get('relationship_counts', {}))} "
        f"proposed_relationships="
        f"{format_compact_counts(summary.get('proposed_relationship_counts', {}))}"
    )


def format_graph_entity_summary(summary):
    return (
        f"records={summary.get('record_count', 0)} "
        f"entities={summary.get('entity_count', 0)} "
        f"counts={format_compact_counts(summary.get('counts', {}))} "
        f"attack_patterns="
        f"{format_entity_entries(summary.get('top_attack_patterns'))} "
        f"threats={format_entity_entries(summary.get('top_threat_actors'))} "
        f"sectors={format_entity_entries(summary.get('top_target_sectors'))}"
    )


def format_entity_entries(entries):
    entries = list(entries or [])
    if not entries:
        return "(none)"
    return ",".join(
        "{}={}".format(
            entry.get("display_name") or entry.get("value") or "(unknown)",
            entry.get("count", 0),
        )
        for entry in entries
    )


def format_compact_counts(counts):
    if not counts:
        return "(none)"
    return ",".join(f"{key}:{counts.get(key, 0)}" for key in sorted(counts))


def format_optional(value):
    return "(none)" if value is None else str(value)


def render_report(report, output_format="text"):
    output_format = normalize_output_format(output_format)
    if output_format == "json":
        return json.dumps(report.to_dict(), sort_keys=True)
    return format_text_report(report)


def normalize_output_format(value):
    output_format = str(value or "text").strip().lower()
    if output_format not in ("text", "json"):
        raise ValueError("output_format must be one of: text,json")
    return output_format


def write_report(report, output_file, output_format="text"):
    output_file = str(output_file or "").strip()
    if not output_file:
        raise ValueError("output_file is required")
    directory = os.path.dirname(output_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(render_report(report, output_format=output_format) + "\n")
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Summarize NarrowCTI decision audit JSONL records."
    )
    parser.add_argument(
        "--file",
        action="append",
        default=[],
        help="Decision audit JSONL file. Can be passed more than once.",
    )
    parser.add_argument(
        "--dir",
        default="",
        help="Directory containing decision audit *.jsonl files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only read the most recent N records. Zero reads all records.",
    )
    parser.add_argument(
        "--reason-limit",
        type=int,
        default=10,
        help="Maximum top reasons to include. Zero includes all reasons.",
    )
    parser.add_argument(
        "--quarantine-limit",
        type=int,
        default=10,
        help="Maximum quarantined candidates to include. Zero includes all candidates.",
    )
    parser.add_argument(
        "--output-file",
        default="",
        help="Optional file path to write the rendered decision audit report.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    paths = list(args.file)
    if args.dir:
        paths.append(args.dir)
    if not paths:
        paths.append(load_settings().decision_audit_dir)

    records = read_decision_records(paths, limit=args.limit or None)
    report = build_decision_audit_report(
        records,
        reason_limit=args.reason_limit,
        quarantine_limit=args.quarantine_limit,
    )
    output_format = "json" if args.json else "text"
    rendered = render_report(report, output_format=output_format)
    if args.output_file:
        write_report(report, args.output_file, output_format=output_format)
    print(rendered)


if __name__ == "__main__":
    main()
