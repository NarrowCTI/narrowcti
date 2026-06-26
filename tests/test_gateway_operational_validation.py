import json
import os
import tempfile
import unittest

from gateway.decisions import build_decision_audit_report
from gateway.operational_validation import (
    build_operational_validation_report,
    check,
    evidence_bool,
    format_html_report,
    format_text_report,
    load_manual_evidence,
    normalize_output_format,
    parse_sources,
    render_report,
    write_report,
)
from gateway.preflight import build_preflight_report
from tests.test_gateway_decisions import (
    decision_record,
    graph_export_plan,
    graph_lookup_matches,
)
from tests.test_gateway_preflight import make_settings


class GatewayOperationalValidationTests(unittest.TestCase):
    def test_builds_pass_report_from_complete_evidence(self):
        preflight = build_preflight_report(
            validation_settings(),
            env={"OTX_DRY_RUN": "true", "MISP_DRY_RUN": "true"},
        )
        decisions = build_decision_audit_report(
            [
                validation_decision("otx"),
                validation_decision("misp"),
            ]
        )

        report = build_operational_validation_report(
            preflight,
            decisions,
            full_validation_passed=True,
            opencti_ui_no_duplicate=True,
            resource_posture_ok=True,
        )
        data = report.to_dict()
        text = format_text_report(report)

        self.assertEqual("pass", data["overall_status"])
        self.assertEqual(8, data["counts"]["pass"])
        self.assertIn("canonical-attack-match status=pass", text)
        json.dumps(data)

    def test_reports_needs_evidence_for_missing_lab_artifacts(self):
        preflight = build_preflight_report(
            validation_settings(enabled_sources=["otx", "misp"]),
            env={"OTX_DRY_RUN": "true", "MISP_DRY_RUN": "true"},
        )
        decisions = build_decision_audit_report([validation_decision("otx")])

        report = build_operational_validation_report(
            preflight,
            decisions,
            required_sources=("otx", "misp"),
        )
        checks = {item.code: item for item in report.checks}

        self.assertEqual("needs-evidence", report.overall_status)
        self.assertEqual(
            "needs-evidence",
            checks["bounded-source-dry-runs"].status,
        )
        self.assertEqual(
            ["misp"],
            checks["bounded-source-dry-runs"].evidence["missing_sources"],
        )
        self.assertEqual(
            "needs-evidence",
            checks["opencti-no-duplicate-attack-pattern"].status,
        )

    def test_flags_unsafe_or_duplicate_conditions_as_failures(self):
        preflight = build_preflight_report(
            validation_settings(enabled_sources=["otx"]),
            env={"OTX_DRY_RUN": "false"},
        )
        decisions = build_decision_audit_report([validation_decision("otx")])

        report = build_operational_validation_report(
            preflight,
            decisions,
            opencti_ui_duplicate_found=True,
            resource_posture_unhealthy=True,
            required_sources=("otx",),
        )
        checks = {item.code: item for item in report.checks}

        self.assertEqual("fail", report.overall_status)
        self.assertEqual("fail", checks["bounded-source-dry-runs"].status)
        self.assertEqual(
            "fail",
            checks["opencti-no-duplicate-attack-pattern"].status,
        )
        self.assertEqual("fail", checks["resource-posture"].status)

    def test_structured_resource_posture_evidence_can_pass(self):
        preflight = build_preflight_report(
            validation_settings(),
            env={"OTX_DRY_RUN": "true", "MISP_DRY_RUN": "true"},
        )
        decisions = build_decision_audit_report(
            [validation_decision("otx"), validation_decision("misp")]
        )

        report = build_operational_validation_report(
            preflight,
            decisions,
            full_validation_passed=True,
            opencti_ui_no_duplicate=True,
            resource_posture_evidence={
                "docker_stats_captured": True,
                "docker_system_df_captured": True,
                "containers_healthy": True,
                "disk_posture_ok": True,
                "docker_stats_command": "docker stats --no-stream",
            },
        )
        checks = {item.code: item for item in report.checks}

        self.assertEqual("pass", checks["resource-posture"].status)
        self.assertEqual(
            "docker stats --no-stream",
            checks["resource-posture"].evidence["resource_posture"][
                "docker_stats_command"
            ],
        )

    def test_structured_resource_posture_evidence_can_fail(self):
        preflight = build_preflight_report(
            validation_settings(),
            env={"OTX_DRY_RUN": "true", "MISP_DRY_RUN": "true"},
        )
        decisions = build_decision_audit_report(
            [validation_decision("otx"), validation_decision("misp")]
        )

        report = build_operational_validation_report(
            preflight,
            decisions,
            full_validation_passed=True,
            opencti_ui_no_duplicate=True,
            resource_posture_evidence={
                "docker_stats_captured": True,
                "docker_system_df_captured": True,
                "containers_healthy": False,
                "disk_posture_ok": True,
            },
        )
        checks = {item.code: item for item in report.checks}

        self.assertEqual("fail", checks["resource-posture"].status)

    def test_parse_sources_normalizes_comma_separated_values(self):
        self.assertEqual(("otx", "misp"), parse_sources(" OTX, misp ,, "))

    def test_loads_manual_evidence_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence_file = os.path.join(tmpdir, "validation-evidence.json")
            with open(evidence_file, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "full_validation_passed": True,
                        "opencti_ui_no_duplicate": "yes",
                        "resource_posture_ok": "true",
                        "resource_posture": {
                            "docker_stats_captured": True,
                            "docker_system_df_captured": True,
                        },
                    },
                    handle,
                )

            evidence = load_manual_evidence(evidence_file)

        self.assertTrue(evidence_bool(evidence, "full_validation_passed"))
        self.assertTrue(evidence_bool(evidence, "opencti_ui_no_duplicate"))
        self.assertTrue(evidence_bool(evidence, "resource_posture_ok"))
        self.assertTrue(evidence["resource_posture"]["docker_stats_captured"])
        self.assertFalse(evidence_bool(evidence, "opencti_ui_duplicate_found"))

    def test_missing_manual_evidence_file_is_empty(self):
        self.assertEqual({}, load_manual_evidence("/missing/validation.json"))

    def test_rejects_non_object_manual_evidence_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence_file = os.path.join(tmpdir, "validation-evidence.json")
            with open(evidence_file, "w", encoding="utf-8") as handle:
                json.dump(["invalid"], handle)

            with self.assertRaises(ValueError):
                load_manual_evidence(evidence_file)

    def test_renders_json_and_text_reports(self):
        report = validation_report()

        text = render_report(report, output_format="text")
        data = json.loads(render_report(report, output_format="json"))

        self.assertIn("NarrowCTI v0.8 operational validation", text)
        self.assertEqual("operational-validation/v0.8", data["schema_version"])

    def test_renders_html_report_with_escaped_dynamic_content(self):
        report = validation_report_with_dynamic_html()

        html = format_html_report(report)

        self.assertIn("<!doctype html>", html)
        self.assertIn("NarrowCTI v0.8 operational validation", html)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert", html)

    def test_rejects_unknown_output_format(self):
        with self.assertRaises(ValueError):
            normalize_output_format("pdf")

    def test_write_report_creates_parent_directory(self):
        report = validation_report()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "evidence", "validation.json")
            result = write_report(report, output_file, output_format="json")
            with open(output_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)

        self.assertEqual(output_file, result)
        self.assertEqual("operational-validation/v0.8", data["schema_version"])


def validation_settings(**overrides):
    values = {
        "enabled_sources": ["otx", "misp"],
        "graph_export_mode": "dry-run",
        "graph_dedup_state_file": "/app/state/graph_dedup.json",
        "opencti_graph_lookup": True,
    }
    values.update(overrides)
    return make_settings(**values)


def validation_report():
    preflight = build_preflight_report(
        validation_settings(),
        env={"OTX_DRY_RUN": "true", "MISP_DRY_RUN": "true"},
    )
    decisions = build_decision_audit_report(
        [
            validation_decision("otx"),
            validation_decision("misp"),
        ]
    )
    return build_operational_validation_report(
        preflight,
        decisions,
        full_validation_passed=True,
        opencti_ui_no_duplicate=True,
        resource_posture_ok=True,
    )


def validation_report_with_dynamic_html():
    report = validation_report()
    return type(report)(
        schema_version=report.schema_version,
        release=report.release,
        overall_status=report.overall_status,
        checks=(
            check(
                "dynamic-html",
                "pass",
                '<script>alert("x")</script>',
                {"path": "C:\\temp\\<customer>"},
            ),
        ),
    )


def validation_decision(source_key):
    return decision_record(
        "2026-06-24T10:01:00Z",
        source_key,
        "dry-run",
        "would ingest",
        query="attack",
        metadata={
            "graph_export_plan": graph_export_plan(
                mode="dry-run",
                status="dry-run",
                candidate_count=1,
                accepted_count=1,
                deduplicated_candidate_count=1,
                deduplicated_entity_count=1,
                actions=["deduplicated"],
                accepted_object_counts={"attack-pattern": 1},
            ),
            "graph_export_plan_lookup_matches": graph_lookup_matches(),
        },
    )


if __name__ == "__main__":
    unittest.main()
