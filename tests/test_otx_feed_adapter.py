import unittest
from types import SimpleNamespace

from core.feed_contract import FeedAdapter, FeedSource
from connectors.otx.feed_adapter import (
    OTXFeedAdapter,
    OTX_SOURCE,
    pulse_to_feed_candidate,
)


class OTXFeedAdapterTests(unittest.TestCase):
    def test_otx_source_has_stable_identity(self):
        self.assertEqual("alienvault:otx", OTX_SOURCE.key)
        self.assertEqual("external_import", OTX_SOURCE.source_type)

    def test_pulse_to_feed_candidate_maps_otx_fields(self):
        candidate = pulse_to_feed_candidate(
            {
                "id": "pulse-1",
                "name": "Fresh infrastructure",
                "description": "description",
                "created": "2026-04-01T00:00:00Z",
                "indicators": [{"type": "domain", "indicator": "example.com"}],
                "tags": ["c2", "malware"],
            }
        )

        self.assertEqual("pulse-1", candidate.external_id)
        self.assertEqual("Fresh infrastructure", candidate.title)
        self.assertEqual("2026-04-01T00:00:00Z", candidate.created)
        self.assertEqual(("c2", "malware"), candidate.tags)
        self.assertEqual(1, len(candidate.indicators))
        self.assertEqual("Fresh infrastructure", candidate.raw["name"])

    def test_pulse_to_feed_candidate_uses_safe_defaults(self):
        candidate = pulse_to_feed_candidate({"id": "pulse-1", "tags": "otx"})

        self.assertEqual("pulse-1", candidate.title)
        self.assertEqual(("otx",), candidate.tags)
        self.assertEqual("", candidate.description)

    def test_adapter_matches_feed_adapter_protocol(self):
        adapter = OTXFeedAdapter(otx_client=SimpleNamespace())

        self.assertIsInstance(adapter, FeedAdapter)

    def test_search_returns_feed_candidates(self):
        otx_client = SimpleNamespace(
            search_pulses=lambda query: [
                {"id": "pulse-1", "name": "One"},
                {"id": "pulse-2", "name": "Two"},
            ]
        )
        adapter = OTXFeedAdapter(otx_client)

        candidates = adapter.search("stealc")

        self.assertEqual(["pulse-1", "pulse-2"], [c.external_id for c in candidates])
        self.assertEqual(["One", "Two"], [c.title for c in candidates])

    def test_enrich_returns_normalized_candidate(self):
        otx_client = SimpleNamespace(
            enrich_pulse=lambda pulse_id: {
                "name": "Enriched",
                "indicators": [{"type": "IPv4", "indicator": "8.8.8.8"}],
            }
        )
        adapter = OTXFeedAdapter(otx_client)
        candidate = pulse_to_feed_candidate({"id": "pulse-1", "name": "Search"})

        enriched = adapter.enrich(candidate)

        self.assertEqual("pulse-1", enriched.external_id)
        self.assertEqual("pulse-1", enriched.raw["id"])
        self.assertEqual("Enriched", enriched.title)
        self.assertEqual(1, len(enriched.indicators))

    def test_enrich_skips_missing_or_failed_pulse(self):
        calls = []
        otx_client = SimpleNamespace(enrich_pulse=lambda pulse_id: calls.append(pulse_id))
        adapter = OTXFeedAdapter(otx_client)

        missing_id = pulse_to_feed_candidate({"name": "No ID"})
        self.assertIsNone(adapter.enrich(missing_id))
        self.assertEqual([], calls)

        failed = pulse_to_feed_candidate({"id": "pulse-1"})
        self.assertIsNone(adapter.enrich(failed))
        self.assertEqual(["pulse-1"], calls)

    def test_adapter_can_use_custom_source(self):
        source = FeedSource(
            name="OTX Premium",
            source_type="commercial_import",
            provider="AlienVault",
            default_confidence=70,
        )
        otx_client = SimpleNamespace(search_pulses=lambda query: [{"id": "pulse-1"}])
        adapter = OTXFeedAdapter(otx_client, source=source)

        candidate = adapter.search("ransomware")[0]

        self.assertEqual("alienvault:otx-premium", candidate.source.key)
        self.assertEqual("commercial_import", candidate.source.source_type)


if __name__ == "__main__":
    unittest.main()
