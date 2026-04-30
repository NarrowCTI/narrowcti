import json
import os
import tempfile
import unittest
from unittest.mock import patch

from connectors.otx.settings import load_settings
from core.policy import should_ingest
from core.state_repository import PulseStateRepository
from exporters.stix_builder import build_report_bundle, indicator_pattern


class PolicyTests(unittest.TestCase):
    def test_hard_filter_can_drop_old_pulses(self):
        pulse = {"created": "2020-01-01T00:00:00Z"}

        decision, reason = should_ingest(
            pulse,
            score=90,
            quarantine_score_threshold=50,
            enable_quarantine=True,
            min_score_to_ingest=60,
            max_days_old=1095,
            min_score_for_old_pulse=80,
            max_days_hard_filter=365,
        )

        self.assertFalse(decision)
        self.assertIn("older than hard filter", reason)

    def test_old_pulse_with_enough_score_can_pass_when_hard_filter_disabled(self):
        pulse = {"created": "2020-01-01T00:00:00Z"}

        decision, reason = should_ingest(
            pulse,
            score=85,
            quarantine_score_threshold=50,
            enable_quarantine=True,
            min_score_to_ingest=60,
            max_days_old=1095,
            min_score_for_old_pulse=80,
            max_days_hard_filter=0,
        )

        self.assertTrue(decision)
        self.assertEqual("ok", reason)


class StateRepositoryTests(unittest.TestCase):
    def test_mark_pulse_is_idempotent_and_persistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            repository = PulseStateRepository(state_file)

            repository.mark_pulse("pulse-1")
            repository.mark_pulse("pulse-1")

            with open(state_file, "r") as f:
                data = json.load(f)

            self.assertEqual(["pulse-1"], data["pulses"])
            self.assertTrue(PulseStateRepository(state_file).has_pulse("pulse-1"))


class SettingsTests(unittest.TestCase):
    def test_load_settings_normalizes_search_limit(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "OTX_API_KEY": "key",
            "OTX_QUERIES": "lummac2, stealc",
            "MAX_PULSES_PER_QUERY": "5",
            "MAX_SEARCH_RESULTS_PER_QUERY": "2",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(["lummac2", "stealc"], settings.otx_queries)
        self.assertEqual(5, settings.max_pulses_per_query)
        self.assertEqual(5, settings.max_search_results_per_query)
        self.assertEqual(3, settings.otx_retries)


class StixBuilderTests(unittest.TestCase):
    def test_indicator_pattern_maps_supported_ioc_types(self):
        self.assertEqual(
            "[domain-name:value = 'example.com']",
            indicator_pattern({"type": "domain", "indicator": "example.com"}),
        )
        self.assertEqual(
            "[file:hashes.SHA256 = 'abc']",
            indicator_pattern({"type": "FileHash-SHA256", "indicator": "abc"}),
        )
        self.assertIsNone(indicator_pattern({"type": "unknown", "indicator": "value"}))

    def test_build_report_bundle_deduplicates_indicators(self):
        bundle, indicator_count = build_report_bundle(
            "Example report",
            "description",
            80,
            [
                {"type": "domain", "indicator": "example.com"},
                {"type": "domain", "indicator": "example.com"},
                {"type": "IPv4", "indicator": "8.8.8.8"},
                {"type": "unsupported", "indicator": "ignored"},
            ],
        )

        data = json.loads(bundle.serialize())
        indicator_objects = [
            item for item in data["objects"] if item["type"] == "indicator"
        ]
        reports = [item for item in data["objects"] if item["type"] == "report"]

        self.assertEqual(2, indicator_count)
        self.assertEqual(2, len(indicator_objects))
        self.assertEqual(2, len(reports[0]["object_refs"]))


if __name__ == "__main__":
    unittest.main()
