import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from connectors.otx.processor import OTXProcessor
from connectors.otx.settings import load_settings
from core.policy import PolicyConfig, should_ingest
from core.state_repository import PulseStateRepository
from exporters.stix_builder import build_report_bundle, indicator_pattern


class PolicyTests(unittest.TestCase):
    def test_hard_filter_can_drop_old_pulses(self):
        pulse = {"created": "2020-01-01T00:00:00Z"}

        decision, reason = should_ingest(
            pulse,
            score=90,
            config=PolicyConfig(
                quarantine_score_threshold=50,
                enable_quarantine=True,
                min_score_to_ingest=60,
                max_days_old=1095,
                min_score_for_old_pulse=80,
                max_days_hard_filter=365,
            ),
        )

        self.assertFalse(decision)
        self.assertIn("older than hard filter", reason)

    def test_old_pulse_with_enough_score_can_pass_when_hard_filter_disabled(self):
        pulse = {"created": "2020-01-01T00:00:00Z"}

        decision, reason = should_ingest(
            pulse,
            score=85,
            config=PolicyConfig(
                quarantine_score_threshold=50,
                enable_quarantine=True,
                min_score_to_ingest=60,
                max_days_old=1095,
                min_score_for_old_pulse=80,
                max_days_hard_filter=0,
            ),
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
        self.assertEqual("OTX Gateway", settings.connector_name)
        self.assertEqual(5, settings.max_pulses_per_query)
        self.assertEqual(5, settings.max_search_results_per_query)
        self.assertEqual(3, settings.otx_retries)


class ProcessorTests(unittest.TestCase):
    def settings(self):
        return SimpleNamespace(
            max_iocs_per_pulse=1,
            quarantine_score_threshold=50,
            enable_quarantine=True,
            min_score_to_ingest=60,
            max_days_old=1095,
            min_score_for_old_pulse=80,
            max_days_hard_filter=0,
            connector_name="Test Connector",
        )

    def test_prepare_candidate_limits_exported_indicators_but_keeps_original_count(self):
        processor = OTXProcessor(
            self.settings(),
            otx_client=None,
            api_client=None,
            logger=None,
        )

        candidate = processor.prepare_candidate(
            "lummac2",
            {
                "name": "LummaC2 sample",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [
                    {"type": "domain", "indicator": "one.example"},
                    {"type": "domain", "indicator": "two.example"},
                ],
            },
        )

        self.assertEqual("LummaC2 sample", candidate.name)
        self.assertEqual(2, candidate.ioc_count)
        self.assertEqual(1, len(candidate.indicators))
        self.assertGreaterEqual(candidate.score, 60)

    def test_process_pulse_skips_missing_id(self):
        logs = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: self.fail("enrich should not be called")
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: self.fail("state should not be queried")
        )
        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client=None,
            logger=logs.append,
        )

        processed = processor.process_pulse("lummac2", {"name": "No ID"}, state)

        self.assertFalse(processed)
        self.assertIn("Skip pulse without id: No ID", logs)

    def test_process_pulse_uses_exporter_and_marks_state_after_success(self):
        logs = []
        marked = []
        export_calls = []
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "name": "LummaC2 fresh",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [{"type": "domain", "indicator": "one.example"}],
            }
        )
        state = SimpleNamespace(
            has_pulse=lambda pulse_id: False,
            mark_pulse=lambda pulse_id: marked.append(pulse_id),
        )

        def exporter(api_client, name, description, score, indicators, identity_name):
            export_calls.append(
                {
                    "api_client": api_client,
                    "name": name,
                    "description": description,
                    "score": score,
                    "indicators": indicators,
                    "identity_name": identity_name,
                }
            )
            return len(indicators)

        processor = OTXProcessor(
            self.settings(),
            otx_client=otx_client,
            api_client="api",
            logger=logs.append,
            exporter=exporter,
        )

        processed = processor.process_pulse(
            "lummac2",
            {"id": "pulse-1", "name": "Search result"},
            state,
        )

        self.assertTrue(processed)
        self.assertEqual(["pulse-1"], marked)
        self.assertEqual("LummaC2 fresh", export_calls[0]["name"])
        self.assertEqual("Test Connector", export_calls[0]["identity_name"])
        self.assertIn("Ingest complete: LummaC2 fresh indicators=1", logs)


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
        identities = [item for item in data["objects"] if item["type"] == "identity"]
        indicator_objects = [
            item for item in data["objects"] if item["type"] == "indicator"
        ]
        reports = [item for item in data["objects"] if item["type"] == "report"]

        self.assertEqual("OTX Gateway", identities[0]["name"])
        self.assertEqual(2, indicator_count)
        self.assertEqual(2, len(indicator_objects))
        self.assertEqual(2, len(reports[0]["object_refs"]))

    def test_build_report_bundle_uses_custom_identity_name(self):
        bundle, _ = build_report_bundle(
            "Example report",
            "description",
            80,
            identity_name="Custom Connector",
        )

        data = json.loads(bundle.serialize())
        identities = [item for item in data["objects"] if item["type"] == "identity"]

        self.assertEqual("Custom Connector", identities[0]["name"])


if __name__ == "__main__":
    unittest.main()
