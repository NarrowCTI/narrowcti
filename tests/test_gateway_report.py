import json
import os
import tempfile
import unittest

from gateway.report import (
    build_value_metrics,
    build_operational_report,
    format_text_report,
    read_gateway_summary_file,
)


class GatewayReportTests(unittest.TestCase):
    def test_report_aggregates_totals_and_sources(self):
        records = [
            gateway_record(
                "2026-06-22T10:00:00Z",
                [
                    source_result("otx", True, reviewed=3, ingested=1, skipped=2),
                    source_result("misp", False, errors=1),
                ],
            ),
            gateway_record(
                "2026-06-22T10:05:00Z",
                [
                    source_result("otx", True, reviewed=2, dropped=1, dry_run=1),
                ],
            ),
        ]

        report = build_operational_report(records)

        self.assertEqual(2, report.run_count)
        self.assertEqual("2026-06-22T10:00:00Z", report.first_recorded_at)
        self.assertEqual("2026-06-22T10:05:00Z", report.last_recorded_at)
        self.assertEqual(5, report.totals["reviewed"])
        self.assertEqual(1, report.totals["ingested"])
        self.assertEqual(1, report.totals["errors"])
        self.assertEqual(2, report.metrics["accepted"])
        self.assertEqual(3, report.metrics["filtered"])
        self.assertEqual(40.0, report.metrics["acceptance_rate_pct"])
        self.assertEqual(60.0, report.metrics["filter_rate_pct"])
        self.assertEqual(2, report.sources["otx"]["runs"])
        self.assertEqual(2, report.sources["otx"]["succeeded"])
        self.assertEqual(2, report.sources["otx"]["metrics"]["accepted"])
        self.assertEqual(3, report.sources["otx"]["metrics"]["filtered"])
        self.assertEqual(1, report.sources["misp"]["failed"])
        self.assertEqual(1, len(report.failures))
        self.assertEqual("misp", report.failures[0]["source_key"])
        self.assertEqual("source offline", report.failures[0]["error"])
        self.assertEqual(1, len(report.sources["misp"]["failures"]))

    def test_empty_report_is_serializable(self):
        report = build_operational_report([])

        self.assertEqual(0, report.run_count)
        self.assertEqual(0, report.metrics["accepted"])
        self.assertEqual(0.0, report.metrics["acceptance_rate_pct"])
        self.assertEqual([], report.failures)
        self.assertEqual({}, report.sources)
        json.dumps(report.to_dict())

    def test_report_records_missing_failure_detail(self):
        records = [
            gateway_record(
                "2026-06-22T10:00:00Z",
                [source_result("misp", False, errors=1, error="")],
            )
        ]

        report = build_operational_report(records)

        self.assertEqual(
            "source failed without error detail",
            report.failures[0]["error"],
        )

    def test_value_metrics_handle_zero_and_error_rates(self):
        metrics = build_value_metrics(
            {
                "reviewed": 4,
                "ingested": 1,
                "dropped": 1,
                "quarantined": 1,
                "skipped": 0,
                "errors": 1,
                "dry_run": 0,
            }
        )

        self.assertEqual(4, metrics["handled"])
        self.assertEqual(1, metrics["accepted"])
        self.assertEqual(2, metrics["filtered"])
        self.assertEqual(25.0, metrics["acceptance_rate_pct"])
        self.assertEqual(50.0, metrics["filter_rate_pct"])
        self.assertEqual(25.0, metrics["error_rate_pct"])

    def test_read_gateway_summary_file_can_limit_recent_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "gateway_runs.jsonl")
            records = [
                gateway_record("2026-06-22T10:00:00Z", [source_result("otx", True)]),
                gateway_record("2026-06-22T10:05:00Z", [source_result("misp", True)]),
            ]
            with open(path, "w", encoding="utf-8") as file_obj:
                for record in records:
                    file_obj.write(json.dumps(record) + "\n")

            limited = read_gateway_summary_file(path, limit=1)

        self.assertEqual(1, len(limited))
        self.assertEqual("2026-06-22T10:05:00Z", limited[0]["recorded_at"])

    def test_text_report_is_operator_readable(self):
        report = build_operational_report(
            [gateway_record("2026-06-22T10:00:00Z", [source_result("otx", True)])]
        )

        text = format_text_report(report)

        self.assertIn("NarrowCTI gateway operational report", text)
        self.assertIn("run_count=1", text)
        self.assertIn("metrics=handled=0 accepted=0 filtered=0", text)
        self.assertIn("- otx runs=1 succeeded=1 failed=0", text)

    def test_text_report_includes_failures(self):
        report = build_operational_report(
            [
                gateway_record(
                    "2026-06-22T10:00:00Z",
                    [source_result("misp", False, errors=1)],
                )
            ]
        )

        text = format_text_report(report)

        self.assertIn("failures:", text)
        self.assertIn("- 2026-06-22T10:00:00Z misp error=source offline", text)


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
    error=None,
):
    return {
        "source_key": source_key,
        "source_name": source_key.upper(),
        "success": success,
        "error": "" if success else error if error is not None else "source offline",
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


if __name__ == "__main__":
    unittest.main()
