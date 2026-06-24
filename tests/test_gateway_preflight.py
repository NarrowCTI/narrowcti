import json
import os
import tempfile
import unittest

from core.mitre_attack import build_attack_cache, save_attack_cache
from gateway.preflight import (
    active_ingestion_mode,
    build_preflight_report,
    format_text_report,
)
from gateway.settings import GatewaySettings


def make_settings(**overrides):
    values = {
        "mode": "gateway",
        "enabled_sources": ["otx"],
        "dry_run": True,
        "run_once": True,
        "source_interval_seconds": 300,
        "state_dir": "/app/state",
        "decision_audit_dir": "/app/state/audit",
        "quarantine_repository_file": "/app/state/quarantine.jsonl",
        "run_summary_file": "/app/state/gateway_runs.jsonl",
        "min_score_to_ingest": 60,
        "enable_quarantine": True,
        "quarantine_score_threshold": 50,
        "max_days_old": 1095,
        "allowed_tlp": ["white", "green"],
        "allowed_indicator_types": ["domain", "ipv4"],
        "dedup_mode": "hybrid",
        "opencti_dedup_lookup": False,
        "dedup_state_file": "/app/state/dedup_index.json",
        "release_audit_file": "/app/state/audit/releases.jsonl",
        "enable_mitre_attack_resolution": True,
        "mitre_cache_file": "",
        "mitre_stix_url": "https://example.com/enterprise-attack.json",
    }
    values.update(overrides)
    return GatewaySettings(**values)


class GatewayPreflightTests(unittest.TestCase):
    def test_preflight_passes_with_safe_gateway_controls(self):
        settings = make_settings(enabled_sources=["otx", "misp"])

        report = build_preflight_report(
            settings,
            env={
                "NARROWCTI_DRY_RUN": "true",
                "MISP_DRY_RUN": "true",
                "MISP_RUN_ONCE": "true",
            },
        )

        self.assertTrue(report.ok)
        self.assertEqual("hybrid", report.ingestion_mode)
        self.assertEqual(("otx", "misp"), report.enabled_sources)
        self.assertEqual("hybrid", report.settings["dedup_mode"])
        self.assertEqual(60, report.settings["min_score_to_ingest"])
        self.assertTrue(report.settings["enable_quarantine"])
        self.assertEqual(["white", "green"], report.settings["allowed_tlp"])
        self.assertEqual(
            ["domain", "ipv4"],
            report.settings["allowed_indicator_types"],
        )
        self.assertEqual("/app/state", report.evidence_paths["state_dir"])
        self.assertEqual(
            "/app/state/quarantine.jsonl",
            report.evidence_paths["quarantine_repository_file"],
        )
        self.assertEqual(
            "/app/state/audit/releases.jsonl",
            report.evidence_paths["release_audit_file"],
        )
        self.assertEqual(
            "/app/state/otx_state.json",
            report.evidence_paths["sources"]["otx"]["state_file"],
        )
        self.assertEqual(
            "/app/state/audit/misp_decisions.jsonl",
            report.evidence_paths["sources"]["misp"]["decision_audit_file"],
        )
        self.assertTrue(report.source_controls["otx"]["dry_run"])
        self.assertTrue(report.source_controls["misp"]["dry_run"])
        self.assertEqual([], [issue for issue in report.issues if issue.severity == "error"])

    def test_preflight_reports_direct_ingestion_mode(self):
        settings = make_settings(enabled_sources=["otx"])

        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertEqual("direct", report.ingestion_mode)
        self.assertEqual("direct", report.to_dict()["ingestion_mode"])

    def test_preflight_reports_misp_collector_ingestion_mode(self):
        settings = make_settings(enabled_sources=["misp"])

        report = build_preflight_report(settings, env={"MISP_DRY_RUN": "true"})

        self.assertEqual("misp-collector", report.ingestion_mode)

    def test_active_ingestion_mode_normalizes_sources(self):
        self.assertEqual("hybrid", active_ingestion_mode([" OTX ", "MISP"]))
        self.assertEqual("misp-collector", active_ingestion_mode(["misp"]))
        self.assertEqual("direct", active_ingestion_mode(["otx", "nvd"]))

    def test_preflight_reports_unknown_sources_as_errors(self):
        settings = make_settings(enabled_sources=["otx", "unknown"])

        report = build_preflight_report(settings, env={"NARROWCTI_DRY_RUN": "true"})

        self.assertFalse(report.ok)
        self.assertIn("unknown-source", [issue.code for issue in report.issues])

    def test_preflight_warns_when_artifact_dedup_is_disabled(self):
        settings = make_settings(dedup_mode="source")

        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertTrue(report.ok)
        self.assertIn("artifact-dedup-disabled", [issue.code for issue in report.issues])

    def test_preflight_warns_when_source_dry_run_is_disabled(self):
        settings = make_settings(enabled_sources=["misp"])

        report = build_preflight_report(settings, env={"MISP_DRY_RUN": "false"})

        self.assertTrue(report.ok)
        self.assertIn("source-dry-run-disabled", [issue.code for issue in report.issues])

    def test_preflight_warns_when_release_audit_is_disabled(self):
        settings = make_settings(release_audit_file="")

        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertTrue(report.ok)
        self.assertIn("release-audit-disabled", [issue.code for issue in report.issues])

    def test_preflight_reports_mitre_resolution_disabled(self):
        settings = make_settings(enable_mitre_attack_resolution=False)

        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertTrue(report.ok)
        self.assertIn(
            "mitre-resolution-disabled",
            [issue.code for issue in report.issues],
        )

    def test_preflight_warns_when_mitre_cache_is_missing(self):
        settings = make_settings(mitre_cache_file="/missing/mitre_attack_cache.json")

        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertTrue(report.ok)
        self.assertIn("mitre-cache-missing", [issue.code for issue in report.issues])

    def test_preflight_warns_when_mitre_cache_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, "mitre_attack_cache.json")
            with open(cache_file, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            settings = make_settings(mitre_cache_file=cache_file)

            report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertTrue(report.ok)
        self.assertIn("mitre-cache-invalid", [issue.code for issue in report.issues])

    def test_preflight_accepts_valid_mitre_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, "mitre_attack_cache.json")
            save_attack_cache(
                build_attack_cache(
                    {
                        "objects": [
                            {
                                "type": "attack-pattern",
                                "id": "attack-pattern--1059",
                                "name": "Command and Scripting Interpreter",
                                "external_references": [
                                    {
                                        "source_name": "mitre-attack",
                                        "external_id": "T1059",
                                    }
                                ],
                                "kill_chain_phases": [
                                    {
                                        "kill_chain_name": "mitre-attack",
                                        "phase_name": "execution",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                cache_file,
            )
            settings = make_settings(mitre_cache_file=cache_file)

            report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        self.assertTrue(report.ok)
        self.assertNotIn(
            "mitre-cache-missing",
            [issue.code for issue in report.issues],
        )
        self.assertNotIn(
            "mitre-cache-invalid",
            [issue.code for issue in report.issues],
        )

    def test_preflight_preserves_source_evidence_overrides(self):
        settings = make_settings(enabled_sources=["otx"])

        report = build_preflight_report(
            settings,
            env={
                "STATE_FILE": "/custom/otx-state.json",
                "DECISION_AUDIT_FILE": "/custom/otx-decisions.jsonl",
                "OTX_DRY_RUN": "true",
            },
        )

        self.assertEqual(
            "/custom/otx-state.json",
            report.evidence_paths["sources"]["otx"]["state_file"],
        )
        self.assertEqual(
            "/custom/otx-decisions.jsonl",
            report.evidence_paths["sources"]["otx"]["decision_audit_file"],
        )

    def test_preflight_reports_empty_state_and_audit_paths(self):
        settings = make_settings(
            state_dir="",
            decision_audit_dir="",
            enabled_sources=["otx"],
        )

        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        codes = [issue.code for issue in report.issues]
        self.assertFalse(report.ok)
        self.assertIn("source-state-disabled", codes)
        self.assertIn("decision-audit-disabled", codes)

    def test_preflight_respects_explicit_empty_source_evidence_overrides(self):
        settings = make_settings(enabled_sources=["otx"])

        report = build_preflight_report(
            settings,
            env={
                "STATE_FILE": "",
                "DECISION_AUDIT_FILE": "",
                "OTX_DRY_RUN": "true",
            },
        )

        codes = [issue.code for issue in report.issues]
        self.assertFalse(report.ok)
        self.assertEqual("", report.evidence_paths["sources"]["otx"]["state_file"])
        self.assertEqual(
            "",
            report.evidence_paths["sources"]["otx"]["decision_audit_file"],
        )
        self.assertIn("source-state-disabled", codes)
        self.assertIn("decision-audit-disabled", codes)

    def test_text_report_and_dict_are_operator_readable(self):
        settings = make_settings(run_summary_file="")
        report = build_preflight_report(settings, env={"OTX_DRY_RUN": "true"})

        text = format_text_report(report)
        data = report.to_dict()

        self.assertIn("NarrowCTI gateway preflight", text)
        self.assertIn("ingestion_mode=direct", text)
        self.assertIn("state_dir=/app/state", text)
        self.assertIn("decision_audit_dir=/app/state/audit", text)
        self.assertIn("run_summary_file=(disabled)", text)
        self.assertIn("quarantine_repository_file=/app/state/quarantine.jsonl", text)
        self.assertIn("release_audit_file=/app/state/audit/releases.jsonl", text)
        self.assertIn("mitre_cache_file=(disabled)", text)
        self.assertIn("enable_mitre_attack_resolution=true", text)
        self.assertIn("dedup_state_file=/app/state/dedup_index.json", text)
        self.assertIn("otx.state_file=/app/state/otx_state.json", text)
        self.assertIn(
            "otx.decision_audit_file=/app/state/audit/otx_decisions.jsonl",
            text,
        )
        self.assertIn("allowed_tlp=white,green", text)
        self.assertIn("allowed_indicator_types=domain,ipv4", text)
        self.assertEqual("", data["settings"]["run_summary_file"])
        self.assertEqual("/app/state", data["evidence_paths"]["state_dir"])
        self.assertEqual(
            "/app/state/quarantine.jsonl",
            data["settings"]["quarantine_repository_file"],
        )
        self.assertEqual(
            "/app/state/audit/releases.jsonl",
            data["settings"]["release_audit_file"],
        )
        json.dumps(data)


if __name__ == "__main__":
    unittest.main()
