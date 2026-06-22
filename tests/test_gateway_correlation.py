import json
import unittest

from core.deduplication import ARTIFACT_RECORDS_KEY, ARTIFACTS_KEY
from gateway.correlation import build_correlation_report, format_text_report


class GatewayCorrelationTests(unittest.TestCase):
    def test_correlation_report_counts_sources_and_multi_source_artifacts(self):
        report = build_correlation_report(sample_state())

        self.assertEqual(3, report.artifact_count)
        self.assertEqual(3, report.record_count)
        self.assertEqual(1, report.correlated_count)
        self.assertEqual(
            {
                "alienvault:otx": 2,
                "misp:misp": 1,
            },
            report.source_counts,
        )
        self.assertEqual("domain:shared.example", report.correlated_artifacts[0]["fingerprint"])
        self.assertEqual(
            ["alienvault:otx", "misp:misp"],
            report.correlated_artifacts[0]["sources"],
        )

    def test_correlation_report_can_limit_output(self):
        state = sample_state()
        state[ARTIFACT_RECORDS_KEY]["ipv4:8.8.8.8"] = {
            "fingerprint": "ipv4:8.8.8.8",
            "sources": ["alienvault:otx", "misp:misp"],
            "sightings": [{}, {}, {}],
            "last_seen": "2026-06-22T10:10:00Z",
        }

        report = build_correlation_report(state, limit=1)

        self.assertEqual(2, report.correlated_count)
        self.assertEqual(1, len(report.correlated_artifacts))
        self.assertEqual("ipv4:8.8.8.8", report.correlated_artifacts[0]["fingerprint"])

    def test_empty_or_legacy_state_is_serializable(self):
        report = build_correlation_report({ARTIFACTS_KEY: ["domain:legacy.example"]})

        self.assertEqual(1, report.artifact_count)
        self.assertEqual(0, report.record_count)
        self.assertEqual(0, report.correlated_count)
        json.dumps(report.to_dict())

    def test_text_report_is_operator_readable(self):
        report = build_correlation_report(sample_state())

        text = format_text_report(report)

        self.assertIn("NarrowCTI artifact correlation report", text)
        self.assertIn("correlated_count=1", text)
        self.assertIn("- alienvault:otx artifacts=2", text)
        self.assertIn("domain:shared.example", text)


def sample_state():
    return {
        ARTIFACTS_KEY: [
            "domain:shared.example",
            "domain:otx-only.example",
            "url:https://example.com/a",
        ],
        ARTIFACT_RECORDS_KEY: {
            "domain:shared.example": {
                "fingerprint": "domain:shared.example",
                "first_seen": "2026-06-22T10:00:00Z",
                "last_seen": "2026-06-22T10:05:00Z",
                "sources": ["alienvault:otx", "misp:misp"],
                "sightings": [
                    {"source_key": "alienvault:otx", "external_id": "pulse-1"},
                    {"source_key": "misp:misp", "external_id": "event-1"},
                ],
            },
            "domain:otx-only.example": {
                "fingerprint": "domain:otx-only.example",
                "sources": ["alienvault:otx"],
                "sightings": [{"source_key": "alienvault:otx"}],
            },
            "url:https://example.com/a": {
                "fingerprint": "url:https://example.com/a",
                "sources": [],
                "sightings": [],
            },
        },
    }


if __name__ == "__main__":
    unittest.main()
