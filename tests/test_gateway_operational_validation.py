import json
import unittest

from gateway.decisions import build_decision_audit_report
from gateway.operational_validation import (
    build_operational_validation_report,
    format_text_report,
    parse_sources,
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

    def test_parse_sources_normalizes_comma_separated_values(self):
        self.assertEqual(("otx", "misp"), parse_sources(" OTX, misp ,, "))


def validation_settings(**overrides):
    values = {
        "enabled_sources": ["otx", "misp"],
        "graph_export_mode": "dry-run",
        "graph_dedup_state_file": "/app/state/graph_dedup.json",
        "opencti_graph_lookup": True,
    }
    values.update(overrides)
    return make_settings(**values)


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
