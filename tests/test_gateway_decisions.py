import json
import os
import tempfile
import unittest

from gateway.decisions import (
    build_decision_audit_report,
    format_text_report,
    read_decision_records,
)


class GatewayDecisionAuditTests(unittest.TestCase):
    def test_report_aggregates_actions_reasons_and_sources(self):
        records = [
            decision_record(
                "2026-06-22T10:00:00Z",
                "otx",
                "drop",
                "below minimum score",
            ),
            decision_record(
                "2026-06-22T10:01:00Z",
                "misp",
                "skip",
                "all indicators already known",
            ),
            decision_record(
                "2026-06-22T10:02:00Z",
                "otx",
                "drop",
                "below minimum score",
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
        self.assertEqual(2, report.sources["otx"]["records"])
        self.assertEqual(1, report.sources["misp"]["actions"]["skip"])
        json.dumps(report.to_dict())

    def test_empty_report_is_serializable(self):
        report = build_decision_audit_report([])

        self.assertEqual(0, report.record_count)
        self.assertEqual({}, report.sources)
        self.assertEqual([], report.reasons)
        json.dumps(report.to_dict())

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
        self.assertIn("- action=quarantine count=1 reason=low score", text)
        self.assertIn("- otx records=1", text)


def decision_record(recorded_at, source_key, action, reason):
    return {
        "recorded_at": recorded_at,
        "source_key": source_key,
        "external_id": "external-1",
        "title": "Sample intelligence",
        "query": "sample",
        "action": action,
        "reason": reason,
        "score": 50,
        "age_days": 1,
        "indicator_count": 1,
        "metadata": {},
    }


def write_records(path, records):
    with open(path, "w", encoding="utf-8") as file_obj:
        for record in records:
            file_obj.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    unittest.main()
