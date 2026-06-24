import json
import os
import tempfile
import unittest

from gateway.diagnostics import (
    build_support_diagnostics,
    format_text_snapshot,
)
from tests.test_gateway_curation_report import (
    decision_record,
    gateway_record,
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
            )

            snapshot = build_support_diagnostics(
                settings,
                env={"OTX_DRY_RUN": "true"},
                generated_at="2026-06-24T10:02:00Z",
            )

        data = snapshot.to_dict()
        inventory = {item["name"]: item for item in data["evidence_inventory"]}

        self.assertEqual("support-diagnostics/v0.8", data["schema_version"])
        self.assertTrue(data["preflight"]["ok"])
        self.assertEqual(1, data["curation_report"]["executive_summary"]["run_count"])
        self.assertEqual(
            1,
            data["curation_report"]["executive_summary"]["decision_record_count"],
        )
        self.assertTrue(inventory["run_summary_file"]["exists"])
        self.assertTrue(inventory["decision_audit_dir"]["exists"])
        json.dumps(data)

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


if __name__ == "__main__":
    unittest.main()
