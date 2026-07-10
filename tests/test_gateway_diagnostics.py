import json
import os
import tempfile
import unittest
import zipfile

from gateway.diagnostics import (
    build_support_diagnostics,
    format_html_snapshot,
    format_text_snapshot,
    normalize_redaction_profile,
    write_html_snapshot,
    write_support_bundle,
)
from tests.test_gateway_curation_report import (
    decision_record,
    gateway_record,
    graph_context_metadata,
    release_event,
    relationship_audit_evidence as incomplete_relationship_audit_evidence,
    source_result,
)
from tests.test_gateway_preflight import make_settings


class GatewayDiagnosticsTests(unittest.TestCase):
    def test_builds_support_snapshot_from_configured_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_dir = os.path.join(tmpdir, "audit")
            os.makedirs(audit_dir)
            summary_file = os.path.join(tmpdir, "gateway_runs.jsonl")
            decision_file = os.path.join(audit_dir, "otx_decisions.jsonl")
            release_audit_file = os.path.join(tmpdir, "releases.jsonl")
            validation_evidence_file = os.path.join(
                tmpdir,
                "operational-validation-evidence.json",
            )
            relationship_audit_file = os.path.join(
                tmpdir,
                "opencti-relationship-audit.json",
            )
            with open(summary_file, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        gateway_record(
                            "2026-06-24T10:00:00Z",
                            [source_result("otx", True, reviewed=2, dry_run=1)],
                        )
                    )
                    + "\n"
                )
            with open(decision_file, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        decision_record(
                            "2026-06-24T10:01:00Z",
                            "otx",
                            "dry-run",
                            "would ingest",
                            metadata=graph_context_metadata(),
                        )
                    )
                    + "\n"
                )
            with open(release_audit_file, "w", encoding="utf-8") as handle:
                for event in [
                    release_event("otx", "reject", reason="Out of scope"),
                    release_event("otx", "reject", reason="Out of scope"),
                    release_event("otx", "reject", reason="No matching sector"),
                ]:
                    handle.write(json.dumps(event) + "\n")
            with open(validation_evidence_file, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "full_validation_passed": True,
                        "opencti_ui_no_duplicate": True,
                        "resource_posture_ok": True,
                    },
                    handle,
                )
            with open(relationship_audit_file, "w", encoding="utf-8") as handle:
                json.dump(relationship_audit_evidence(), handle)
            settings = make_settings(
                state_dir=tmpdir,
                decision_audit_dir=audit_dir,
                run_summary_file=summary_file,
                quarantine_repository_file=os.path.join(tmpdir, "quarantine.jsonl"),
                release_audit_file=release_audit_file,
            )

            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                operational_validation_evidence_file=validation_evidence_file,
                opencti_relationship_audit_file=relationship_audit_file,
            )

        data = snapshot.to_dict()
        inventory = {item["name"]: item for item in data["evidence_inventory"]}
        validation_checks = {
            item["code"]: item
            for item in data["operational_validation"]["checks"]
        }
        warning_codes = [item["code"] for item in data["support_warnings"]]

        self.assertEqual("support-diagnostics/v0.8", data["schema_version"])
        self.assertEqual("none", data["redaction_profile"])
        self.assertTrue(data["preflight"]["ok"])
        self.assertEqual(
            "curation-report/v0.8",
            data["curation_report"]["schema_version"],
        )
        self.assertEqual("none", data["curation_report"]["redaction_profile"])
        self.assertTrue(
            data["curation_report"]["redaction_policy"]["raw_evidence_included"]
        )
        self.assertEqual(1, data["curation_report"]["executive_summary"]["run_count"])
        self.assertEqual(
            1,
            data["curation_report"]["executive_summary"]["decision_record_count"],
        )
        self.assertTrue(inventory["run_summary_file"]["exists"])
        self.assertTrue(inventory["decision_audit_dir"]["exists"])
        self.assertTrue(inventory["operational_validation_evidence_file"]["exists"])
        self.assertTrue(inventory["opencti_relationship_audit_file"]["exists"])
        self.assertEqual(
            "otx",
            data["curation_report"]["source_summaries"][0]["source_key"],
        )
        self.assertTrue(
            data["curation_report"]["graph_validation"]["relationship_audit"][
                "available"
            ]
        )
        self.assertEqual(
            "needs-evidence",
            data["operational_validation"]["overall_status"],
        )
        self.assertEqual("pass", validation_checks["full-validation"]["status"])
        self.assertEqual(
            "pass",
            validation_checks["opencti-no-duplicate-attack-pattern"]["status"],
        )
        self.assertEqual("pass", validation_checks["resource-posture"]["status"])
        self.assertEqual(
            "pass",
            validation_checks["opencti-relationship-audit"]["status"],
        )
        self.assertIn("operational-validation-needs-evidence", warning_codes)
        self.assertIn("graph_validation:", format_text_snapshot(snapshot))
        self.assertIn("source_posture:", format_text_snapshot(snapshot))
        self.assertIn("policy_insights:", format_text_snapshot(snapshot))
        self.assertIn(
            "scores=records=1 min=70 max=70 average=70.0 low=0",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "graph=candidates=2 density=2.0",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "accepted_relationship_types=uses:2",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "stix_object_types=attack-pattern:1,malware:1",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "context=records=1 accepted_context=3 density=3.0",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "narrative=records=1 entities=4 attack_patterns=Command and Scripting Interpreter:1",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "arsenal=Loader Example:1",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "threats=APT Example:1 sectors=Finance:1",
            format_text_snapshot(snapshot),
        )
        self.assertIn(
            "top_reasons=reject:Out of scope=2",
            format_text_snapshot(snapshot),
        )
        self.assertIn("operational_validation:", format_text_snapshot(snapshot))
        self.assertIn("Source Posture", format_html_snapshot(snapshot))
        self.assertIn("Graph Validation", format_html_snapshot(snapshot))
        self.assertIn("Policy Insights", format_html_snapshot(snapshot))
        self.assertIn("Out of scope", format_html_snapshot(snapshot))
        self.assertIn("Operational Validation", format_html_snapshot(snapshot))
        json.dumps(data)

    def test_support_warnings_surface_incomplete_graph_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            relationship_audit_file = os.path.join(
                tmpdir,
                "opencti-relationship-audit.json",
            )
            with open(relationship_audit_file, "w", encoding="utf-8") as handle:
                json.dump(incomplete_relationship_audit_evidence(), handle)
            settings = make_settings(
                state_dir=tmpdir,
                decision_audit_dir=os.path.join(tmpdir, "missing-audit"),
                run_summary_file=os.path.join(tmpdir, "missing-runs.jsonl"),
                quarantine_repository_file=os.path.join(
                    tmpdir,
                    "missing-quarantine.jsonl",
                ),
                release_audit_file=os.path.join(tmpdir, "missing-releases.jsonl"),
            )

            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                opencti_relationship_audit_file=relationship_audit_file,
            )

        data = snapshot.to_dict()
        warning_codes = [item["code"] for item in data["support_warnings"]]
        audit = data["curation_report"]["graph_validation"]["relationship_audit"]

        self.assertEqual("needs-evidence", audit["coverage_status"])
        self.assertEqual(["adversary", "victimology"], audit["missing_quadrants"])
        self.assertIn("curation-graph-validation-incomplete", warning_codes)
        self.assertIn("coverage=needs-evidence", format_text_snapshot(snapshot))

    def test_reports_missing_evidence_as_support_warning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = make_settings(
                state_dir=tmpdir,
                decision_audit_dir=os.path.join(tmpdir, "missing-audit"),
                run_summary_file=os.path.join(tmpdir, "missing-runs.jsonl"),
                quarantine_repository_file=os.path.join(tmpdir, "missing-quarantine.jsonl"),
                release_audit_file=os.path.join(tmpdir, "missing-releases.jsonl"),
            )

            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
            )

        codes = [item["code"] for item in snapshot.support_warnings]
        text = format_text_snapshot(snapshot)

        self.assertIn("missing-configured-evidence", codes)
        self.assertIn("curation-evidence-missing", codes)
        self.assertIn("NarrowCTI support diagnostics", text)
        self.assertIn("evidence_inventory:", text)

    def test_support_redaction_masks_paths_and_preserves_open_source_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_dir = os.path.join(tmpdir, "audit")
            os.makedirs(audit_dir)
            summary_file = os.path.join(tmpdir, "gateway_runs.jsonl")
            decision_file = os.path.join(audit_dir, "otx_decisions.jsonl")
            with open(summary_file, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        gateway_record(
                            "2026-06-24T10:00:00Z",
                            [source_result("otx", True, reviewed=1, dry_run=1)],
                        )
                    )
                    + "\n"
                )
            with open(decision_file, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        decision_record(
                            "2026-06-24T10:01:00Z",
                            "otx",
                            "quarantine",
                            "local path " + tmpdir,
                        )
                    )
                    + "\n"
                )
            settings = make_settings(
                state_dir=tmpdir,
                decision_audit_dir=audit_dir,
                run_summary_file=summary_file,
                quarantine_repository_file=os.path.join(tmpdir, "quarantine.jsonl"),
                release_audit_file=os.path.join(audit_dir, "releases.jsonl"),
                declared_capabilities=["source.otx", "graph.lookup.opencti"],
                graph_export_mode="dry-run",
                graph_dedup_state_file=os.path.join(tmpdir, "graph_dedup.json"),
                opencti_graph_lookup=True,
            )

            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                redaction_profile="support",
            )

        data = snapshot.to_dict()
        serialized = json.dumps(data)

        self.assertEqual("support", data["redaction_profile"])
        self.assertEqual("support", data["curation_report"]["redaction_profile"])
        self.assertFalse(
            data["curation_report"]["redaction_policy"]["raw_evidence_included"]
        )
        self.assertEqual("open_source", data["preflight"]["settings"]["distribution_model"])
        self.assertTrue(data["preflight"]["settings"]["open_source"])
        self.assertEqual(
            ["source.otx", "graph.lookup.opencti"],
            data["preflight"]["settings"]["capability_inventory"]["requested_capabilities"],
        )
        self.assertNotIn(tmpdir, serialized)
        self.assertIn("[redacted-path]", serialized)
        self.assertEqual([], data["curation_report"]["decisions"]["quarantined"])
        self.assertEqual([], data["curation_report"]["decisions"]["queries"])
        self.assertEqual(1, data["curation_report"]["executive_summary"]["run_count"])
        self.assertIn("operational_validation", data)
        self.assertIn("redaction_profile=support", format_text_snapshot(snapshot))
        self.assertIn("curation_report_profile=support", format_text_snapshot(snapshot))
        self.assertIn("NarrowCTI support diagnostics", format_html_snapshot(snapshot))

    def test_external_redaction_masks_paths_and_preserves_open_source_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_dir = os.path.join(tmpdir, "audit")
            os.makedirs(audit_dir)
            summary_file = os.path.join(tmpdir, "gateway_runs.jsonl")
            decision_file = os.path.join(audit_dir, "otx_decisions.jsonl")
            with open(summary_file, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        gateway_record(
                            "2026-06-24T10:00:00Z",
                            [source_result("otx", True, reviewed=1, dry_run=1)],
                        )
                    )
                    + "\n"
                )
            with open(decision_file, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        decision_record(
                            "2026-06-24T10:01:00Z",
                            "otx",
                            "quarantine",
                            "local path " + tmpdir,
                        )
                    )
                    + "\n"
                )
            settings = make_settings(
                state_dir=tmpdir,
                decision_audit_dir=audit_dir,
                run_summary_file=summary_file,
                quarantine_repository_file=os.path.join(tmpdir, "quarantine.jsonl"),
                release_audit_file=os.path.join(audit_dir, "releases.jsonl"),
                declared_capabilities=["source.otx"],
            )

            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                redaction_profile="external",
            )

        data = snapshot.to_dict()
        serialized = json.dumps(data)

        self.assertEqual("external", data["redaction_profile"])
        self.assertEqual("external", data["curation_report"]["redaction_profile"])
        self.assertEqual(
            "external-recipient",
            data["curation_report"]["redaction_policy"]["audience"],
        )
        self.assertEqual("open_source", data["preflight"]["settings"]["distribution_model"])
        self.assertTrue(data["preflight"]["settings"]["open_source"])
        self.assertEqual(
            ["source.otx"],
            data["preflight"]["settings"]["capability_inventory"]["requested_capabilities"],
        )
        self.assertNotIn(tmpdir, serialized)
        self.assertIn("[redacted-path]", serialized)
        self.assertEqual([], data["curation_report"]["decisions"]["quarantined"])
        self.assertEqual([], data["curation_report"]["decisions"]["queries"])
        self.assertIn("redaction_profile=external", format_text_snapshot(snapshot))
        self.assertIn("curation_report_profile=external", format_text_snapshot(snapshot))
        self.assertIn("NarrowCTI support diagnostics", format_html_snapshot(snapshot))

    def test_rejects_unknown_redaction_profile(self):
        with self.assertRaises(ValueError):
            normalize_redaction_profile("unsafe")

    def test_support_bundle_contains_only_redacted_snapshot_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = make_settings(
                state_dir=tmpdir,
                decision_audit_dir=os.path.join(tmpdir, "audit"),
                run_summary_file=os.path.join(tmpdir, "gateway_runs.jsonl"),
                quarantine_repository_file=os.path.join(tmpdir, "quarantine.jsonl"),
            )
            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                redaction_profile="support",
            )
            bundle_file = os.path.join(tmpdir, "support.zip")

            result = write_support_bundle(snapshot, bundle_file)

            with zipfile.ZipFile(bundle_file) as archive:
                names = sorted(archive.namelist())
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
                snapshot_data = archive.read("support-diagnostics.json").decode("utf-8")
                snapshot_text = archive.read("support-diagnostics.txt").decode("utf-8")
                snapshot_html = archive.read("support-diagnostics.html").decode("utf-8")

        self.assertEqual(
            [
                "manifest.json",
                "support-diagnostics.html",
                "support-diagnostics.json",
                "support-diagnostics.txt",
            ],
            names,
        )
        self.assertFalse(manifest["raw_evidence_included"])
        self.assertEqual("support", manifest["redaction_profile"])
        self.assertEqual(result["files"], manifest["files"])
        self.assertNotIn(tmpdir, snapshot_data)
        self.assertIn("[redacted-path]", snapshot_data)
        self.assertIn("redaction_profile=support", snapshot_text)
        self.assertIn("Source Posture", snapshot_html)
        self.assertIn("Policy Insights", snapshot_html)
        self.assertIn("Operational Validation", snapshot_html)
        self.assertIn("<!doctype html>", snapshot_html)
        self.assertIn("redaction_profile", snapshot_html)

    def test_support_bundle_rejects_unredacted_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot = build_support_diagnostics(
                make_settings(state_dir=tmpdir),
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
            )

            with self.assertRaises(ValueError):
                write_support_bundle(snapshot, os.path.join(tmpdir, "support.zip"))

    def test_write_html_snapshot_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot = build_support_diagnostics(
                make_settings(state_dir=tmpdir),
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                redaction_profile="support",
            )
            html_file = os.path.join(tmpdir, "diagnostics", "support.html")

            result = write_html_snapshot(snapshot, html_file)

            with open(html_file, "r", encoding="utf-8") as handle:
                html = handle.read()

        self.assertEqual(html_file, result)
        self.assertIn("<!doctype html>", html)
        self.assertIn("NarrowCTI support diagnostics", html)
        self.assertIn("redaction_profile", html)

    def test_html_snapshot_escapes_dynamic_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot = build_support_diagnostics(
                make_settings(
                    state_dir=tmpdir,
                    enabled_sources=["otx", "<script>alert(1)</script>"],
                ),
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
                redaction_profile="support",
            )

        html = format_html_snapshot(snapshot)

        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)


def relationship_audit_evidence():
    return {
        "found": True,
        "target": {
            "entity_type": "Infrastructure",
            "name": "MISP ip-port 137.184.181.252",
        },
        "relationship_count": 30,
        "outbound_count": 25,
        "inbound_count": 5,
        "diamond_quadrant_counts": {
            "adversary": 0,
            "capability": 28,
            "infrastructure": 1,
            "victimology": 0,
            "other": 1,
        },
        "kill_chain_attack_patterns": ["T1090 Proxy"],
    }


if __name__ == "__main__":
    unittest.main()
