import json
import os
import tempfile
import unittest

from core.quarantine import QuarantineRecord, QuarantineRepository
from gateway.curation_report import (
    build_curation_report,
    build_curation_report_from_files,
    format_html_report,
    format_text_report,
    normalize_redaction_profile,
    report_to_dict,
    write_html_report,
)
from gateway.decisions import build_decision_audit_report
from gateway.report import build_operational_report
from gateway.review import ReviewSummary


class GatewayCurationReportTests(unittest.TestCase):
    def test_builds_executive_summary_from_existing_reports(self):
        operational = build_operational_report(
            [
                gateway_record(
                    "2026-06-24T10:00:00Z",
                    [
                        source_result(
                            "otx",
                            True,
                            reviewed=4,
                            ingested=1,
                            dropped=1,
                            quarantined=1,
                            dry_run=1,
                        )
                    ],
                )
            ]
        )
        decisions = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-24T10:01:00Z",
                    "otx",
                    "quarantine",
                    "below threshold",
                    metadata=graph_metadata(),
                )
            ]
        )
        review = ReviewSummary(
            record_count=1,
            status_counts={"pending": 1},
            source_counts={"otx": 1},
            pending_count=1,
            exportable_count=0,
        )

        report = build_curation_report(
            operational,
            decisions,
            review,
            generated_at="2026-06-24T10:02:00Z",
        )
        summary = report.executive_summary
        source_summary = report.source_summaries[0]

        self.assertEqual(1, summary["run_count"])
        self.assertEqual(4, summary["reviewed_count"])
        self.assertEqual(2, summary["accepted_count"])
        self.assertEqual(2, summary["filtered_count"])
        self.assertEqual(1, summary["quarantine_decision_count"])
        self.assertEqual(1, summary["pending_review_count"])
        self.assertEqual(2, summary["graph_candidate_count"])
        self.assertEqual(1, summary["graph_lookup_match_count"])
        self.assertEqual(1, summary["graph_would_create_object_count"])
        self.assertEqual("otx", source_summary["source_key"])
        self.assertEqual("stable", source_summary["posture"])
        self.assertEqual(4, source_summary["reviewed"])
        self.assertEqual(2, source_summary["accepted"])
        self.assertEqual(1, source_summary["decision_records"])
        self.assertEqual(1, source_summary["quarantine_records"])
        self.assertIn(
            "review-quarantine",
            [item["code"] for item in report.recommendations],
        )
        self.assertIn(
            "validate-graph-promotion",
            [item["code"] for item in report.recommendations],
        )
        json.dumps(report.to_dict())

    def test_executive_summary_uses_current_graph_stix_preview_keys(self):
        operational = build_operational_report([])
        decisions = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-24T10:01:00Z",
                    "otx",
                    "dry-run",
                    "would preview graph",
                    metadata={
                        "graph_stix_preview": {
                            "status": "dry-run",
                            "bundle_type": "bundle",
                            "accepted_candidate_count": 2,
                            "bundle_object_count": 7,
                            "graph_object_count": 3,
                            "graph_relationship_count": 4,
                        }
                    },
                )
            ]
        )
        review = ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )

        report = build_curation_report(operational, decisions, review)
        summary = report.executive_summary
        text = format_text_report(report)

        self.assertEqual(1, summary["graph_stix_bundle_count"])
        self.assertEqual(3, summary["graph_stix_object_count"])
        self.assertEqual(4, summary["graph_stix_relationship_count"])
        self.assertIn("stix_bundles=1 stix_objects=3 stix_relationships=4", text)

    def test_builds_report_from_files_with_partial_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_file = os.path.join(tmpdir, "gateway_runs.jsonl")
            decision_file = os.path.join(tmpdir, "otx_decisions.jsonl")
            quarantine_file = os.path.join(tmpdir, "quarantine.jsonl")
            with open(summary_file, "w", encoding="utf-8") as file_obj:
                file_obj.write(
                    json.dumps(
                        gateway_record(
                            "2026-06-24T10:00:00Z",
                            [source_result("otx", True, reviewed=1, dry_run=1)],
                        )
                    )
                    + "\n"
                )
            with open(decision_file, "w", encoding="utf-8") as file_obj:
                file_obj.write(
                    json.dumps(
                        decision_record(
                            "2026-06-24T10:01:00Z",
                            "otx",
                            "dry-run",
                            "would ingest",
                        )
                    )
                    + "\n"
                )
            QuarantineRepository(quarantine_file).add(
                QuarantineRecord(
                    source_key="otx",
                    external_id="pulse-1",
                    title="Sample pulse",
                    reason="low score",
                )
            )

            report = build_curation_report_from_files(
                summary_file=summary_file,
                decision_paths=[decision_file],
                quarantine_file=quarantine_file,
            )

        self.assertEqual(1, report.executive_summary["run_count"])
        self.assertEqual(1, report.executive_summary["decision_record_count"])
        self.assertEqual(1, report.executive_summary["pending_review_count"])
        self.assertEqual(1, report.source_summaries[0]["pending_review"])

    def test_support_redaction_removes_detailed_lists(self):
        operational = build_operational_report(
            [
                gateway_record(
                    "2026-06-24T10:00:00Z",
                    [
                        source_result(
                            "otx",
                            False,
                            errors=1,
                        )
                    ],
                )
            ]
        )
        decisions = build_decision_audit_report(
            [
                decision_record(
                    "2026-06-24T10:01:00Z",
                    "otx",
                    "quarantine",
                    "sensitive local finding",
                )
            ]
        )
        review = ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )
        report = build_curation_report(operational, decisions, review)

        redacted = report_to_dict(report, redaction_profile="support")
        text = format_text_report(report, redaction_profile="support")
        html = format_html_report(report, redaction_profile="support")

        self.assertEqual([], redacted["operational"]["failures"])
        self.assertEqual([], redacted["operational"]["queries"])
        self.assertEqual([], redacted["operational"]["sources"]["otx"]["failures"])
        self.assertEqual([], redacted["decisions"]["quarantined"])
        self.assertEqual([], redacted["decisions"]["queries"])
        self.assertEqual(1, redacted["executive_summary"]["decision_record_count"])
        self.assertIn("NarrowCTI curation report", text)
        self.assertIn("NarrowCTI curation report", html)

    def test_rejects_unknown_redaction_profile(self):
        with self.assertRaises(ValueError):
            normalize_redaction_profile("external")

    def test_builds_review_action_summary_from_release_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            release_audit_file = os.path.join(tmpdir, "releases.jsonl")
            with open(release_audit_file, "w", encoding="utf-8") as file_obj:
                for event in [
                    release_event("otx", "release", released=3, reason="In scope"),
                    release_event("otx", "reject", reason="Noisy source"),
                    release_event("misp", "reject", reason="Out of scope"),
                    release_event("misp", "export", exported=2, duplicates=1),
                ]:
                    file_obj.write(json.dumps(event) + "\n")

            report = build_curation_report_from_files(
                release_audit_file=release_audit_file,
            )

        summary = report.executive_summary
        actions = report.analyst_review_actions
        policy_insights = {
            insight["source_key"]: insight for insight in report.policy_insights
        }
        recommendation_codes = [item["code"] for item in report.recommendations]

        self.assertEqual(4, summary["review_action_count"])
        self.assertEqual(1, summary["review_release_count"])
        self.assertEqual(2, summary["review_reject_count"])
        self.assertEqual(1, summary["review_export_count"])
        self.assertEqual(33.33, summary["review_release_rate_pct"])
        self.assertEqual(66.67, summary["review_reject_rate_pct"])
        self.assertEqual(3, actions["released_indicator_count"])
        self.assertEqual(2, actions["exported_indicator_count"])
        self.assertEqual(1, actions["dedup_duplicate_count"])
        self.assertEqual({"misp": 2, "otx": 2}, actions["source_counts"])
        self.assertEqual(
            {"reject": 1, "export": 1},
            actions["source_action_counts"]["misp"],
        )
        self.assertEqual(
            [{"reason": "Out of scope", "count": 1}],
            actions["source_top_reasons"]["misp"]["reject"],
        )
        self.assertEqual(
            [
                {
                    "action": "reject",
                    "reason": "Out of scope",
                    "count": 1,
                }
            ],
            policy_insights["misp"]["top_reasons"],
        )
        self.assertEqual("info", policy_insights["misp"]["severity"])
        self.assertEqual("observe-review-pattern", policy_insights["misp"]["signal"])
        self.assertEqual(100.0, policy_insights["misp"]["reject_rate_pct"])
        self.assertEqual("info", policy_insights["otx"]["severity"])
        source_postures = {
            source["source_key"]: source["posture"]
            for source in report.source_summaries
        }
        self.assertEqual("needs-attention", source_postures["misp"])
        self.assertEqual("stable", source_postures["otx"])
        self.assertIn("tune-curation-policy", recommendation_codes)

    def test_policy_insights_identify_repeated_rejects(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            release_audit_file = os.path.join(tmpdir, "releases.jsonl")
            decision_file = os.path.join(tmpdir, "misp_decisions.jsonl")
            with open(release_audit_file, "w", encoding="utf-8") as file_obj:
                for event in [
                    release_event("misp", "reject", reason="Out of scope"),
                    release_event("misp", "reject", reason="Out of scope"),
                    release_event("misp", "reject", reason="No matching sector"),
                ]:
                    file_obj.write(json.dumps(event) + "\n")
            with open(decision_file, "w", encoding="utf-8") as file_obj:
                for score in (30, 40, 80):
                    file_obj.write(
                        json.dumps(
                            decision_record(
                                "2026-06-24T10:01:00Z",
                                "misp",
                                "quarantine",
                                "low score",
                                metadata=graph_context_metadata(),
                                score=score,
                            )
                        )
                        + "\n"
                    )

            report = build_curation_report_from_files(
                decision_paths=[decision_file],
                release_audit_file=release_audit_file,
            )

        insight = report.policy_insights[0]
        text = format_text_report(report)
        html = format_html_report(report)
        recommendation_codes = [item["code"] for item in report.recommendations]

        self.assertEqual("misp", insight["source_key"])
        self.assertEqual("high", insight["severity"])
        self.assertEqual(
            "policy-too-permissive-or-source-too-noisy",
            insight["signal"],
        )
        self.assertEqual(100.0, insight["reject_rate_pct"])
        self.assertEqual(50.0, insight["score_summary"]["average_score"])
        self.assertEqual(2, insight["low_score_count"])
        self.assertEqual(6, insight["graph_evidence"]["candidate_count"])
        self.assertEqual(2.0, insight["graph_evidence"]["candidate_density"])
        self.assertEqual(3, insight["graph_evidence"]["lookup_match_count"])
        self.assertEqual(100.0, insight["graph_evidence"]["lookup_match_rate_pct"])
        self.assertEqual(9, insight["context_quality"]["accepted_candidate_count"])
        self.assertEqual(3.0, insight["context_quality"]["candidate_density"])
        self.assertEqual(
            [{"category": "ttp", "count": 6}, {"category": "threat", "count": 3}],
            insight["context_quality"]["top_categories"],
        )
        self.assertEqual(
            [{"action": "quarantine", "reason": "low score", "count": 3}],
            insight["top_quarantine_reasons"],
        )
        self.assertEqual(
            [
                {
                    "action": "reject",
                    "reason": "Out of scope",
                    "count": 2,
                },
                {
                    "action": "reject",
                    "reason": "No matching sector",
                    "count": 1,
                },
            ],
            insight["top_reasons"],
        )
        self.assertIn("scores=records=3 min=30 max=80 average=50.0 low=2", text)
        self.assertIn("graph=candidates=6 density=2.0", text)
        self.assertIn("context=records=3 accepted_context=9 density=3.0", text)
        self.assertIn("categories=ttp:6,threat:3", text)
        self.assertIn("quarantine_reasons=quarantine:low score=3", text)
        self.assertIn("top_reasons=reject:Out of scope=2", text)
        self.assertIn("Out of scope", html)
        self.assertIn("review-source-policy-insights", recommendation_codes)

    def test_policy_insights_identify_frequent_analyst_releases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            release_audit_file = os.path.join(tmpdir, "releases.jsonl")
            with open(release_audit_file, "w", encoding="utf-8") as file_obj:
                for event in [
                    release_event("otx", "release", released=1),
                    release_event("otx", "release", released=2),
                    release_event("otx", "release-indicators", released=1),
                ]:
                    file_obj.write(json.dumps(event) + "\n")

            report = build_curation_report_from_files(
                release_audit_file=release_audit_file,
            )

        insight = report.policy_insights[0]
        text = format_text_report(report)
        html = format_html_report(report)

        self.assertEqual("otx", insight["source_key"])
        self.assertEqual("medium", insight["severity"])
        self.assertEqual("policy-may-be-too-strict", insight["signal"])
        self.assertEqual(100.0, insight["release_rate_pct"])
        self.assertIn("policy_insights:", text)
        self.assertIn("Policy Insights", html)

    def test_text_report_is_analyst_readable(self):
        operational = build_operational_report([])
        decisions = build_decision_audit_report([])
        review = ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )

        text = format_text_report(
            build_curation_report(
                operational,
                decisions,
                review,
                generated_at="2026-06-24T10:02:00Z",
            )
        )

        self.assertIn("NarrowCTI curation report", text)
        self.assertIn("executive_summary:", text)
        self.assertIn("analyst_review:", text)
        self.assertIn("review_actions=", text)
        self.assertIn("graph_readiness:", text)
        self.assertNotIn("source_summaries:", text)
        self.assertNotIn("policy_insights:", text)
        self.assertIn("collect-evidence", text)

    def test_html_report_is_analyst_readable(self):
        operational = build_operational_report([])
        decisions = build_decision_audit_report([])
        review = ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )

        html = format_html_report(
            build_curation_report(
                operational,
                decisions,
                review,
                generated_at="2026-06-24T10:02:00Z",
            )
        )

        self.assertIn("<!doctype html>", html)
        self.assertIn("NarrowCTI curation report", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Analyst Review Actions", html)
        self.assertIn("Graph Readiness", html)
        self.assertIn("Source Summaries", html)
        self.assertIn("Policy Insights", html)
        self.assertIn("collect-evidence", html)

    def test_html_report_escapes_dynamic_content(self):
        operational = build_operational_report([])
        decisions = build_decision_audit_report([])
        review = ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )

        html = format_html_report(
            build_curation_report(
                operational,
                decisions,
                review,
                generated_at="<script>alert(1)</script>",
            )
        )

        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_write_html_report_creates_parent_directory(self):
        operational = build_operational_report([])
        decisions = build_decision_audit_report([])
        review = ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )
        report = build_curation_report(
            operational,
            decisions,
            review,
            generated_at="2026-06-24T10:02:00Z",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            html_file = os.path.join(tmpdir, "reports", "curation.html")
            result = write_html_report(report, html_file)
            with open(html_file, "r", encoding="utf-8") as handle:
                html = handle.read()

        self.assertEqual(html_file, result)
        self.assertIn("NarrowCTI curation report", html)


def gateway_record(recorded_at, results):
    return {
        "recorded_at": recorded_at,
        "sources": len(results),
        "succeeded": sum(1 for result in results if result["success"]),
        "failed": sum(1 for result in results if not result["success"]),
        "totals": merge_result_totals(results),
        "results": results,
    }


def source_result(
    source_key,
    success,
    reviewed=0,
    ingested=0,
    dropped=0,
    quarantined=0,
    skipped=0,
    errors=0,
    dry_run=0,
):
    return {
        "source_key": source_key,
        "source_name": source_key.upper(),
        "success": success,
        "error": "" if success else "source offline",
        "summary_count": 1 if success else 0,
        "totals": {
            "reviewed": reviewed,
            "ingested": ingested,
            "dropped": dropped,
            "quarantined": quarantined,
            "skipped": skipped,
            "errors": errors,
            "dry_run": dry_run,
        },
        "summaries": [],
    }


def merge_result_totals(results):
    totals = {
        "reviewed": 0,
        "ingested": 0,
        "dropped": 0,
        "quarantined": 0,
        "skipped": 0,
        "errors": 0,
        "dry_run": 0,
    }
    for result in results:
        for field_name, value in result["totals"].items():
            totals[field_name] += value
    return totals


def decision_record(recorded_at, source_key, action, reason, metadata=None, score=70):
    return {
        "recorded_at": recorded_at,
        "source_key": source_key,
        "query": "sample",
        "action": action,
        "reason": reason,
        "title": "Sample intelligence",
        "external_id": "external-1",
        "indicator_count": 1,
        "score": score,
        "metadata": metadata or {},
    }


def release_event(
    source_key,
    action,
    released=0,
    exported=0,
    duplicates=0,
    reason="reviewed",
):
    return {
        "recorded_at": "2026-06-24T10:03:00Z",
        "quarantine_id": "q-1",
        "status": "released",
        "action": action,
        "reviewer": "analyst",
        "reason": reason,
        "source_key": source_key,
        "external_id": "external-1",
        "released_indicator_count": released,
        "exported_indicator_count": exported,
        "dedup_duplicate_count": duplicates,
    }


def graph_metadata():
    return {
        "graph_export_plan": {
            "mode": "dry-run",
            "status": "dry-run",
            "candidate_count": 2,
            "accepted_count": 1,
            "held_count": 1,
            "would_create_object_count": 1,
            "would_create_relationship_count": 2,
            "actions": [{"action": "would_create"}, {"action": "held"}],
        },
        "graph_export_plan_lookup_matches": [
            {
                "stix_object_type": "attack-pattern",
                "match": {
                    "match_type": "external_id",
                    "entity_type": "Attack-Pattern",
                },
            }
        ],
    }


def graph_context_metadata():
    metadata = graph_metadata()
    metadata["contextual_scoring"] = {
        "mode": "dry-run",
        "status": "dry-run",
        "base_score": 55,
        "contextual_score": 80,
        "score_delta": 25,
        "accepted_candidate_count": 3,
        "adjustment_count": 2,
        "category_counts": {"threat": 1, "ttp": 2},
        "capped": False,
        "applied_to_decision": False,
    }
    return metadata


if __name__ == "__main__":
    unittest.main()
