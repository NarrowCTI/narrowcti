import json
import os
import tempfile
import unittest

from gateway.decisions import (
    build_contextual_scoring_summary,
    build_decision_audit_report,
    build_graph_export_summary,
    build_graph_stix_preview_summary,
    build_score_summary,
    format_text_report,
    read_decision_records,
    render_report,
    write_report,
)


class GatewayDecisionAuditTests(unittest.TestCase):
    def test_report_aggregates_actions_reasons_and_sources(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "drop",
                "below minimum score",
                score=30,
            ),
            decision_record(
                "2026-06-22T10:01:00Z",
                "misp",
                "skip",
                "all indicators already known",
                score=90,
            ),
            decision_record(
                "2026-06-22T10:02:00Z",
                "otx",
                "drop",
                "below minimum score",
                score=50,
            ),
        ]

        report = build_decision_audit_report(records)

        self.assertEqual(3, report.record_count)
        self.assertEqual("2026-06-22T10:00:00Z", report.first_recorded_at)
        self.assertEqual("2026-06-22T10:02:00Z", report.last_recorded_at)
        self.assertEqual(2, report.actions["drop"])
        self.assertEqual(1, report.actions["skip"])
        self.assertEqual(
            {"action": "drop", "reason": "below minimum score", "count": 2},
            report.reasons[0],
        )
        self.assertEqual(3, report.score_summary["overall"]["records_with_score"])
        self.assertEqual(30, report.score_summary["overall"]["min_score"])
        self.assertEqual(90, report.score_summary["overall"]["max_score"])
        self.assertEqual(56.67, report.score_summary["overall"]["average_score"])
        self.assertEqual(1, report.score_summary["overall"]["bands"]["30-49"])
        self.assertEqual(
            2,
            report.score_summary["by_action"]["drop"]["records_with_score"],
        )
        self.assertEqual(2, report.sources["otx"]["records"])
        self.assertEqual(
            2,
            report.sources["otx"]["score_summary"]["records_with_score"],
        )
        self.assertEqual(
            {"below minimum score": 2},
            report.sources["otx"]["action_reasons"]["drop"],
        )
        self.assertEqual(1, report.sources["misp"]["actions"]["skip"])
        self.assertEqual([], report.quarantined)
        self.assertEqual(0, report.graph_export["record_count"])
        self.assertEqual(0, report.contextual_scoring["record_count"])
        self.assertEqual(0, report.graph_stix_preview["record_count"])
        self.assertEqual(2, len(report.queries))
        self.assertEqual("otx", report.queries[0]["source_key"])
        self.assertEqual("sample", report.queries[0]["query"])
        self.assertEqual(2, report.queries[0]["records"])
        self.assertEqual(2, report.queries[0]["actions"]["drop"])
        self.assertEqual(
            2,
            report.queries[0]["score_summary"]["records_with_score"],
        )
        json.dumps(report.to_dict())

    def test_report_normalizes_legacy_dry_run_action(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "misp",
                "dry_run",
                "ok",
                score=70,
            ),
        ]

        report = build_decision_audit_report(records)

        self.assertEqual(1, report.actions["dry-run"])
        self.assertNotIn("dry_run", report.actions)
        self.assertEqual(
            {"action": "dry-run", "reason": "ok", "count": 1},
            report.reasons[0],
        )
        self.assertEqual(1, report.sources["misp"]["actions"]["dry-run"])
        self.assertEqual(1, report.queries[0]["actions"]["dry-run"])
        self.assertEqual(
            1,
            report.score_summary["by_action"]["dry-run"]["records_with_score"],
        )

    def test_report_aggregates_graph_export_plan_metadata(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "dry-run",
                "ok",
                metadata={
                    "graph_export_plan": graph_export_plan(
                        mode="dry-run",
                        status="dry-run",
                        candidate_count=3,
                        accepted_count=2,
                        held_count=1,
                        deduplicated_candidate_count=1,
                        deduplicated_entity_count=1,
                        deduplicated_relationship_count=1,
                        would_create_object_count=2,
                        would_create_relationship_count=2,
                        actions=["would_create", "would_create", "held"],
                        held_reasons={"entity_confidence_below_min": 1},
                        accepted_object_counts={"attack-pattern": 1, "malware": 1},
                        accepted_relationship_counts={"uses": 2},
                    ),
                    "graph_export_plan_lookup_matches": graph_lookup_matches(),
                },
                query="lummac2",
            ),
            decision_record(
                "2026-06-22T10:01:00Z",
                "misp",
                "ingest",
                "ok",
                metadata={
                    "graph_export_plan": graph_export_plan(
                        mode="audit",
                        status="audit-only",
                        candidate_count=1,
                        accepted_count=1,
                        held_count=0,
                        actions=["audit_only"],
                        accepted_object_counts={"identity": 1},
                        accepted_relationship_counts={"originated-from": 1},
                    )
                },
                query="tlp:green",
            ),
        ]

        report = build_decision_audit_report(records)
        graph = report.graph_export

        self.assertEqual(2, graph["record_count"])
        self.assertEqual(4, graph["candidate_count"])
        self.assertEqual(3, graph["accepted_count"])
        self.assertEqual(1, graph["held_count"])
        self.assertEqual(1, graph["deduplicated_candidate_count"])
        self.assertEqual(1, graph["deduplicated_entity_count"])
        self.assertEqual(1, graph["deduplicated_relationship_count"])
        self.assertEqual(2, graph["would_create_object_count"])
        self.assertEqual(2, graph["would_create_relationship_count"])
        self.assertEqual(1, graph["lookup_match_count"])
        self.assertEqual({"attack-pattern": 1}, graph["lookup_match_object_counts"])
        self.assertEqual({"mitre_attack_id": 1}, graph["lookup_match_type_counts"])
        self.assertEqual(
            {"Attack-Pattern": 1},
            graph["lookup_canonical_entity_counts"],
        )
        self.assertEqual({"audit": 1, "dry-run": 1}, graph["modes"])
        self.assertEqual({"audit-only": 1, "dry-run": 1}, graph["statuses"])
        self.assertEqual(
            {"audit_only": 1, "held": 1, "would_create": 2},
            graph["actions"],
        )
        self.assertEqual({"entity_confidence_below_min": 1}, graph["held_reasons"])
        self.assertEqual(3, graph["by_source"]["otx"]["candidate_count"])
        self.assertEqual(1, graph["by_source"]["misp"]["candidate_count"])
        by_query = {
            (item["source_key"], item["query"]): item
            for item in graph["by_query"]
        }
        self.assertEqual(3, by_query[("otx", "lummac2")]["candidate_count"])
        self.assertEqual(1, by_query[("otx", "lummac2")]["lookup_match_count"])
        self.assertEqual(1, by_query[("misp", "tlp:green")]["candidate_count"])

    def test_graph_export_summary_ignores_records_without_plan(self):
        summary = build_graph_export_summary(
            [decision_record("2026-06-22T10:00:00Z", "otx", "drop", "old")]
        )

        self.assertEqual(0, summary["record_count"])
        self.assertEqual({}, summary["by_source"])
        self.assertEqual([], summary["by_query"])

    def test_report_aggregates_contextual_scoring_metadata(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "dry-run",
                "ok",
                metadata={
                    "contextual_scoring": contextual_scoring(
                        accepted_candidate_count=4,
                        adjustment_count=3,
                        score_delta=30,
                        contextual_score=90,
                        category_counts={"threat": 1, "ttp": 2},
                    )
                },
                query="lummac2",
            ),
            decision_record(
                "2026-06-22T10:01:00Z",
                "misp",
                "ingest",
                "ok",
                metadata={
                    "contextual_scoring": contextual_scoring(
                        accepted_candidate_count=2,
                        adjustment_count=1,
                        score_delta=10,
                        contextual_score=80,
                        category_counts={"author": 1},
                        capped=True,
                    )
                },
                query="tlp:green",
            ),
        ]

        report = build_decision_audit_report(records)
        contextual = report.contextual_scoring

        self.assertEqual(2, contextual["record_count"])
        self.assertEqual(6, contextual["accepted_candidate_count"])
        self.assertEqual(4, contextual["adjustment_count"])
        self.assertEqual(40, contextual["score_delta_total"])
        self.assertEqual(20.0, contextual["average_score_delta"])
        self.assertEqual(90, contextual["max_contextual_score"])
        self.assertEqual(1, contextual["capped_count"])
        self.assertEqual(0, contextual["applied_to_decision_count"])
        self.assertEqual({"dry-run": 2}, contextual["modes"])
        self.assertEqual({"dry-run": 2}, contextual["statuses"])
        self.assertEqual(
            {"author": 1, "threat": 1, "ttp": 2},
            contextual["category_counts"],
        )
        self.assertEqual(4, contextual["by_source"]["otx"]["accepted_candidate_count"])
        self.assertEqual(2, contextual["by_source"]["misp"]["accepted_candidate_count"])
        by_query = {
            (item["source_key"], item["query"]): item
            for item in contextual["by_query"]
        }
        self.assertEqual(3, by_query[("otx", "lummac2")]["adjustment_count"])
        self.assertEqual(1, by_query[("misp", "tlp:green")]["adjustment_count"])

    def test_contextual_scoring_summary_ignores_records_without_metadata(self):
        summary = build_contextual_scoring_summary(
            [decision_record("2026-06-22T10:00:00Z", "otx", "drop", "old")]
        )

        self.assertEqual(0, summary["record_count"])
        self.assertEqual({}, summary["by_source"])
        self.assertEqual([], summary["by_query"])

    def test_report_aggregates_graph_stix_preview_metadata(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "dry-run",
                "ok",
                metadata={
                    "graph_stix_preview": graph_stix_preview(
                        accepted_candidate_count=4,
                        bundle_object_count=8,
                        graph_object_count=3,
                        graph_relationship_count=3,
                        semantic_relationship_count=2,
                        report_relationship_count=1,
                        skipped_candidate_count=1,
                        object_counts={"attack-pattern": 1, "malware": 2},
                        relationship_counts={"related-to": 1, "uses": 2},
                        proposed_relationship_counts={"uses": 3},
                    )
                },
                query="lummac2",
            ),
            decision_record(
                "2026-06-22T10:01:00Z",
                "misp",
                "ingest",
                "ok",
                metadata={
                    "graph_stix_preview": graph_stix_preview(
                        accepted_candidate_count=2,
                        bundle_object_count=4,
                        graph_object_count=1,
                        graph_relationship_count=1,
                        report_relationship_count=1,
                        object_counts={"identity": 1},
                        relationship_counts={"related-to": 1},
                        proposed_relationship_counts={"originated-from": 1},
                    )
                },
                query="tlp:green",
            ),
        ]

        report = build_decision_audit_report(records)
        preview = report.graph_stix_preview

        self.assertEqual(2, preview["record_count"])
        self.assertEqual(6, preview["accepted_candidate_count"])
        self.assertEqual(12, preview["bundle_object_count"])
        self.assertEqual(4, preview["graph_object_count"])
        self.assertEqual(4, preview["graph_relationship_count"])
        self.assertEqual(2, preview["semantic_relationship_count"])
        self.assertEqual(2, preview["report_relationship_count"])
        self.assertEqual(1, preview["skipped_candidate_count"])
        self.assertEqual({"preview": 2}, preview["statuses"])
        self.assertEqual({"bundle": 2}, preview["bundle_types"])
        self.assertEqual(
            {"attack-pattern": 1, "identity": 1, "malware": 2},
            preview["object_counts"],
        )
        self.assertEqual(
            {"related-to": 2, "uses": 2},
            preview["relationship_counts"],
        )
        self.assertEqual(
            {"originated-from": 1, "uses": 3},
            preview["proposed_relationship_counts"],
        )
        self.assertEqual(4, preview["by_source"]["otx"]["accepted_candidate_count"])
        self.assertEqual(2, preview["by_source"]["misp"]["accepted_candidate_count"])
        by_query = {
            (item["source_key"], item["query"]): item
            for item in preview["by_query"]
        }
        self.assertEqual(8, by_query[("otx", "lummac2")]["bundle_object_count"])
        self.assertEqual(4, by_query[("misp", "tlp:green")]["bundle_object_count"])

    def test_graph_stix_preview_summary_ignores_records_without_metadata(self):
        summary = build_graph_stix_preview_summary(
            [decision_record("2026-06-22T10:00:00Z", "otx", "drop", "old")]
        )

        self.assertEqual(0, summary["record_count"])
        self.assertEqual({}, summary["by_source"])
        self.assertEqual([], summary["by_query"])

    def test_score_summary_ignores_records_without_score(self):
        summary = build_score_summary(
            [
                {"score": 20},
                {"score": "80"},
                {"score": None},
                {"score": "not-a-score"},
            ]
        )

        self.assertEqual(2, summary["records_with_score"])
        self.assertEqual(20, summary["min_score"])
        self.assertEqual(80, summary["max_score"])
        self.assertEqual(50.0, summary["average_score"])
        self.assertEqual(1, summary["bands"]["0-29"])
        self.assertEqual(1, summary["bands"]["70-89"])

    def test_empty_report_is_serializable(self):
        report = build_decision_audit_report([])

        self.assertEqual(0, report.record_count)
        self.assertEqual({}, report.sources)
        self.assertEqual([], report.reasons)
        self.assertEqual([], report.quarantined)
        self.assertEqual([], report.queries)
        self.assertEqual(0, report.score_summary["overall"]["records_with_score"])
        self.assertEqual(0, report.graph_export["record_count"])
        self.assertEqual(0, report.contextual_scoring["record_count"])
        self.assertEqual(0, report.graph_stix_preview["record_count"])
        json.dumps(report.to_dict())

    def test_report_lists_recent_quarantined_candidates(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "quarantine",
                "low score",
                score=30,
            ),
            decision_record(
                "2026-06-22T10:05:00Z",
                "misp",
                "quarantine",
                "low score",
                score=40,
                metadata={"tags": ["tlp:green"]},
            ),
            decision_record(
                "2026-06-22T10:06:00Z",
                "otx",
                "drop",
                "tlp blocked",
                score=80,
            ),
        ]

        report = build_decision_audit_report(records, quarantine_limit=1)

        self.assertEqual(1, len(report.quarantined))
        self.assertEqual("misp", report.quarantined[0]["source_key"])
        self.assertEqual("external-1", report.quarantined[0]["external_id"])
        self.assertEqual("Sample intelligence", report.quarantined[0]["title"])
        self.assertEqual("sample", report.quarantined[0]["query"])
        self.assertEqual("low score", report.quarantined[0]["reason"])
        self.assertEqual(40, report.quarantined[0]["score"])
        self.assertEqual(1, report.quarantined[0]["age_days"])
        self.assertEqual(1, report.quarantined[0]["indicator_count"])
        self.assertEqual(["tlp:green"], report.quarantined[0]["metadata"]["tags"])

    def test_report_aggregates_decisions_by_source_query(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "ingest",
                "ok",
                score=80,
                query="lummac2",
            ),
            decision_record(
                "2026-06-22T10:01:00Z",
                "otx",
                "quarantine",
                "low score",
                score=35,
                query="lummac2",
            ),
            decision_record(
                "2026-06-22T10:02:00Z",
                "misp",
                "skip",
                "all indicators already known",
                score=90,
                query="tlp:green",
            ),
        ]

        report = build_decision_audit_report(records)

        self.assertEqual(2, len(report.queries))
        self.assertEqual("otx", report.queries[0]["source_key"])
        self.assertEqual("lummac2", report.queries[0]["query"])
        self.assertEqual(2, report.queries[0]["records"])
        self.assertEqual(1, report.queries[0]["actions"]["ingest"])
        self.assertEqual(1, report.queries[0]["actions"]["quarantine"])
        self.assertEqual({"ok": 1, "low score": 1}, report.queries[0]["reasons"])
        self.assertEqual(
            2,
            report.queries[0]["score_summary"]["records_with_score"],
        )
        self.assertEqual(35, report.queries[0]["score_summary"]["min_score"])
        self.assertEqual(80, report.queries[0]["score_summary"]["max_score"])

    def test_read_decision_records_can_expand_directory_and_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            otx_path = os.path.join(tmpdir, "otx_decisions.jsonl")
            misp_path = os.path.join(tmpdir, "misp_decisions.jsonl")
            write_records(
                otx_path,
                [decision_record("2026-06-22T10:00:00Z", "otx", "ingest", "ok")],
            )
            write_records(
                misp_path,
                [decision_record("2026-06-22T10:05:00Z", "misp", "drop", "old")],
            )

            records = read_decision_records([tmpdir], limit=1)

        self.assertEqual(1, len(records))
        self.assertEqual("misp", records[0]["source_key"])

    def test_missing_directory_returns_no_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_dir = os.path.join(tmpdir, "audit")

            records = read_decision_records([missing_dir])

        self.assertEqual([], records)

    def test_text_report_is_operator_readable(self):
        report = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-22T10:00:00Z",
                    "otx",
                    "quarantine",
                    "low score",
                )
            ]
        )

        text = format_text_report(report)

        self.assertIn("NarrowCTI decision audit report", text)
        self.assertIn("record_count=1", text)
        self.assertIn("actions=ingest=0 drop=0 quarantine=1", text)
        self.assertIn("scores=records_with_score=1 min_score=50", text)
        self.assertIn("- action=quarantine count=1 reason=low score", text)
        self.assertIn("quarantine_candidates:", text)
        self.assertIn(
            "- 2026-06-22T10:00:00Z otx external_id=external-1",
            text,
        )
        self.assertIn("queries:", text)
        self.assertIn("- otx query=sample records=1", text)
        self.assertIn("- otx records=1", text)

    def test_renders_and_writes_decision_report_files(self):
        report = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-22T10:00:00Z",
                    "otx",
                    "dry-run",
                    "would ingest",
                )
            ]
        )

        text = render_report(report, output_format="text")
        data = json.loads(render_report(report, output_format="json"))

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "reports", "decisions.json")
            result = write_report(report, output_file, output_format="json")
            with open(output_file, "r", encoding="utf-8") as handle:
                written = json.load(handle)

        self.assertIn("NarrowCTI decision audit report", text)
        self.assertEqual(1, data["record_count"])
        self.assertEqual(output_file, result)
        self.assertEqual(1, written["record_count"])

    def test_text_report_includes_graph_export_summary(self):
        report = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-22T10:00:00Z",
                    "otx",
                    "dry-run",
                    "ok",
                    metadata={
                        "graph_export_plan": graph_export_plan(
                            mode="dry-run",
                            status="dry-run",
                            candidate_count=2,
                            accepted_count=2,
                            held_count=0,
                            deduplicated_candidate_count=1,
                            deduplicated_entity_count=1,
                            deduplicated_relationship_count=0,
                            would_create_object_count=2,
                            would_create_relationship_count=1,
                            actions=["would_create", "would_create"],
                            accepted_object_counts={"attack-pattern": 2},
                            accepted_relationship_counts={"uses": 1},
                        ),
                        "graph_export_plan_lookup_matches": graph_lookup_matches(),
                    },
                )
            ]
        )

        text = format_text_report(report)

        self.assertIn("graph_export:", text)
        self.assertIn("deduplicated=1", text)
        self.assertIn("would_create_objects=2", text)
        self.assertIn("lookup_matches=1", text)
        self.assertIn("lookup_match_types=mitre_attack_id:1", text)
        self.assertIn("actions=would_create:2", text)
        self.assertIn("graph_export_by_source:", text)

    def test_text_report_includes_contextual_scoring_summary(self):
        report = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-22T10:00:00Z",
                    "otx",
                    "dry-run",
                    "ok",
                    metadata={
                        "contextual_scoring": contextual_scoring(
                            accepted_candidate_count=3,
                            adjustment_count=2,
                            score_delta=25,
                            contextual_score=85,
                            category_counts={"threat": 1, "ttp": 1},
                        )
                    },
                )
            ]
        )

        text = format_text_report(report)

        self.assertIn("contextual_scoring:", text)
        self.assertIn("score_delta_total=25", text)
        self.assertIn("max_contextual_score=85", text)
        self.assertIn("categories=threat:1,ttp:1", text)
        self.assertIn("contextual_scoring_by_source:", text)

    def test_text_report_includes_graph_stix_preview_summary(self):
        report = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-22T10:00:00Z",
                    "otx",
                    "dry-run",
                    "ok",
                    metadata={
                        "graph_stix_preview": graph_stix_preview(
                            accepted_candidate_count=3,
                            bundle_object_count=6,
                            graph_object_count=2,
                            graph_relationship_count=2,
                            skipped_candidate_count=1,
                            object_counts={"attack-pattern": 1},
                            relationship_counts={"uses": 1},
                        )
                    },
                )
            ]
        )

        text = format_text_report(report)

        self.assertIn("graph_stix_preview:", text)
        self.assertIn("bundle_objects=6", text)
        self.assertIn("skipped_candidates=1", text)
        self.assertIn("objects=attack-pattern:1", text)
        self.assertIn("graph_stix_preview_by_source:", text)


def decision_record(
    recorded_at,
    source_key,
    action,
    reason,
    score=50,
    metadata=None,
    query="sample",
):
    return {
        "recorded_at": recorded_at,
        "source_key": source_key,
        "external_id": "external-1",
        "title": "Sample intelligence",
        "query": query,
        "action": action,
        "reason": reason,
        "score": score,
        "age_days": 1,
        "indicator_count": 1,
        "metadata": metadata or {},
    }


def graph_export_plan(
    mode="audit",
    status="audit-only",
    candidate_count=0,
    accepted_count=0,
    held_count=0,
    deduplicated_candidate_count=0,
    deduplicated_entity_count=0,
    deduplicated_relationship_count=0,
    would_create_object_count=0,
    would_create_relationship_count=0,
    actions=None,
    held_reasons=None,
    accepted_object_counts=None,
    accepted_relationship_counts=None,
):
    return {
        "version": "v0.7.0-dev",
        "mode": mode,
        "status": status,
        "export_enabled": False,
        "candidate_count": candidate_count,
        "accepted_count": accepted_count,
        "held_count": held_count,
        "deduplicated_candidate_count": deduplicated_candidate_count,
        "deduplicated_entity_count": deduplicated_entity_count,
        "deduplicated_relationship_count": deduplicated_relationship_count,
        "held_reasons": held_reasons or {},
        "accepted_object_counts": accepted_object_counts or {},
        "accepted_relationship_counts": accepted_relationship_counts or {},
        "would_create_object_count": would_create_object_count,
        "would_create_relationship_count": would_create_relationship_count,
        "actions": [{"action": action} for action in actions or []],
    }


def graph_lookup_matches():
    return [
        {
            "entity_key": "entity:attack-pattern:t1059",
            "stix_object_type": "attack-pattern",
            "value": "T1059",
            "match": {
                "opencti_id": "internal--1",
                "standard_id": "attack-pattern--1111",
                "entity_type": "Attack-Pattern",
                "name": "Command and Scripting Interpreter",
                "x_mitre_id": "T1059",
                "match_type": "mitre_attack_id",
                "match_value": "T1059",
            },
        }
    ]


def contextual_scoring(
    accepted_candidate_count=0,
    adjustment_count=0,
    score_delta=0,
    contextual_score=50,
    category_counts=None,
    capped=False,
):
    return {
        "version": "v0.7.0-dev",
        "mode": "dry-run",
        "status": "dry-run",
        "applied_to_decision": False,
        "base_score": max(0, contextual_score - score_delta),
        "contextual_score": contextual_score,
        "score_delta": score_delta,
        "accepted_candidate_count": accepted_candidate_count,
        "adjustment_count": adjustment_count,
        "category_counts": category_counts or {},
        "raw_impact_total": 0,
        "capped_impact_total": 0,
        "max_impact": 100,
        "impact_ratio": 0,
        "capped": capped,
        "adjustments": [],
    }


def graph_stix_preview(
    accepted_candidate_count=0,
    bundle_object_count=0,
    graph_object_count=0,
    graph_relationship_count=0,
    semantic_relationship_count=0,
    report_relationship_count=0,
    skipped_candidate_count=0,
    object_counts=None,
    relationship_counts=None,
    proposed_relationship_counts=None,
):
    return {
        "status": "preview",
        "export_enabled": False,
        "bundle_type": "bundle",
        "accepted_candidate_count": accepted_candidate_count,
        "bundle_object_count": bundle_object_count,
        "graph_object_count": graph_object_count,
        "graph_relationship_count": graph_relationship_count,
        "semantic_relationship_count": semantic_relationship_count,
        "report_relationship_count": report_relationship_count,
        "skipped_candidate_count": skipped_candidate_count,
        "object_counts": object_counts or {},
        "relationship_counts": relationship_counts or {},
        "proposed_relationship_counts": proposed_relationship_counts or {},
        "skipped_candidates": [],
    }


def write_records(path, records):
    with open(path, "w", encoding="utf-8") as file_obj:
        for record in records:
            file_obj.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    unittest.main()
