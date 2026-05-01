import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from connectors.otx.runtime import run_processor_loop
from connectors.otx.settings import load_settings
from core.feed_contract import (
    FeedAdapter,
    FeedCandidate,
    FeedRunSummary,
    FeedSource,
)
from core.policy import PolicyConfig, should_ingest
from core.state_repository import PulseStateRepository
from exporters.stix_builder import build_report_bundle, indicator_pattern


class FeedContractTests(unittest.TestCase):
    def test_feed_source_builds_stable_key(self):
        source = FeedSource(
            name="OTX Custom",
            source_type="external_import",
            provider="AlienVault",
        )

        self.assertEqual("alienvault:otx-custom", source.key)

    def test_feed_candidate_normalizes_collections(self):
        source = FeedSource(name="MISP Feed", source_type="external_import")
        candidate = FeedCandidate(
            source=source,
            external_id="event-1",
            title="Suspicious infrastructure",
            indicators=[{"type": "domain", "indicator": "example.com"}],
            tags=["misp", "infrastructure"],
        )

        self.assertEqual("local:misp-feed", candidate.source.key)
        self.assertIsInstance(candidate.indicators, tuple)
        self.assertIsInstance(candidate.tags, tuple)
        self.assertEqual(1, len(candidate.indicators))

    def test_feed_run_summary_counts_handled_candidates(self):
        source = FeedSource(name="OTX Custom", source_type="external_import")
        summary = FeedRunSummary(
            source=source,
            query="stealc",
            available=10,
            reviewed=5,
            ingested=2,
            dropped=2,
            quarantined=1,
        )

        self.assertEqual(5, summary.handled)

    def test_feed_adapter_protocol_accepts_matching_adapter(self):
        class DummyAdapter:
            source = FeedSource(name="Dummy", source_type="test")

            def search(self, query):
                return []

            def enrich(self, candidate):
                return candidate

        self.assertIsInstance(DummyAdapter(), FeedAdapter)


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
            "INGEST_PAUSE_SECONDS": "4",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(["lummac2", "stealc"], settings.otx_queries)
        self.assertEqual("NarrowCTI OTX Connector", settings.connector_name)
        self.assertEqual(5, settings.max_pulses_per_query)
        self.assertEqual(5, settings.max_search_results_per_query)
        self.assertEqual(3, settings.otx_retries)
        self.assertEqual(4, settings.ingest_pause_seconds)


class RuntimeTests(unittest.TestCase):
    def test_run_processor_loop_runs_cycle_and_sleeps(self):
        calls = []
        processor = SimpleNamespace(run_once=lambda: calls.append("run_once"))
        settings = SimpleNamespace(connector_run_interval=15)

        def sleeper(seconds):
            calls.append(("sleep", seconds))
            raise StopIteration

        with self.assertRaises(StopIteration):
            run_processor_loop(processor, settings, calls.append, sleeper=sleeper)

        self.assertEqual(["run_once", "Sleeping 15s", ("sleep", 15)], calls)


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

        self.assertEqual("NarrowCTI OTX Connector", identities[0]["name"])
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
