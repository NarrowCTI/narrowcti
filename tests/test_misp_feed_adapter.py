import unittest
from types import SimpleNamespace

from connectors.misp.client import MISPClient
from connectors.misp.feed_adapter import (
    MISPFeedAdapter,
    MISP_SOURCE,
    attribute_to_indicators,
    event_to_feed_candidate,
)
from core.feed_contract import FeedAdapter, FeedSource


class MISPFeedAdapterTests(unittest.TestCase):
    def test_misp_source_has_stable_identity(self):
        self.assertEqual("misp:misp", MISP_SOURCE.key)
        self.assertEqual("external_import", MISP_SOURCE.source_type)

    def test_event_to_feed_candidate_maps_event_fields(self):
        event = {
            "id": "42",
            "uuid": "event-uuid",
            "info": "AlienVault pulse imported into MISP",
            "date": "2026-06-21",
            "Orgc": {"name": "AlienVault"},
            "Tag": [{"name": "tlp:white"}, {"name": "misp:tool=otx"}],
            "Attribute": [
                {
                    "uuid": "attr-1",
                    "type": "domain",
                    "category": "Network activity",
                    "value": "example.com",
                    "to_ids": True,
                },
                {
                    "uuid": "attr-2",
                    "type": "ip-src",
                    "value": "8.8.8.8",
                    "to_ids": True,
                    "first_seen": "2026-06-20T10:00:00Z",
                    "last_seen": "2026-06-21T10:00:00Z",
                    "Tag": [{"name": "confidence:high"}],
                },
                {
                    "uuid": "attr-3",
                    "type": "link",
                    "category": "External analysis",
                    "value": "https://example.com/report",
                    "to_ids": False,
                },
            ],
        }

        candidate = event_to_feed_candidate(event)

        self.assertEqual("event-uuid", candidate.external_id)
        self.assertEqual("AlienVault pulse imported into MISP", candidate.title)
        self.assertEqual("2026-06-21", candidate.created)
        self.assertEqual(("tlp:white", "misp:tool=otx"), candidate.tags)
        self.assertEqual(["domain", "ipv4"], [ioc["type"] for ioc in candidate.indicators])
        self.assertEqual("misp", candidate.raw["provenance"]["collector"])
        self.assertEqual("AlienVault", candidate.raw["provenance"]["original_source"])
        self.assertEqual("2026-06-20T10:00:00Z", candidate.indicators[1]["first_seen"])
        self.assertEqual(["confidence:high"], candidate.indicators[1]["tags"])

    def test_attribute_to_indicators_maps_composite_values(self):
        domain_ip = attribute_to_indicators(
            {"type": "domain|ip", "value": "example.org|2001:4860:4860::8888", "to_ids": True}
        )
        filename_hash = attribute_to_indicators(
            {"type": "filename|sha256", "value": "payload.exe|" + "a" * 64, "to_ids": True}
        )
        ip_port = attribute_to_indicators(
            {"type": "ip-dst|port", "value": "192.0.2.10|443", "to_ids": True}
        )

        self.assertEqual(["domain", "ipv6"], [ioc["type"] for ioc in domain_ip])
        self.assertEqual("filehash-sha256", filename_hash[0]["type"])
        self.assertEqual("a" * 64, filename_hash[0]["indicator"])
        self.assertEqual("ipv4", ip_port[0]["type"])
        self.assertEqual("192.0.2.10", ip_port[0]["indicator"])

    def test_adapter_matches_feed_adapter_protocol(self):
        adapter = MISPFeedAdapter(misp_client=SimpleNamespace())

        self.assertIsInstance(adapter, FeedAdapter)

    def test_search_returns_feed_candidates(self):
        misp_client = SimpleNamespace(
            search_events=lambda query: [
                {"uuid": "event-1", "info": "One"},
                {"uuid": "event-2", "info": "Two"},
            ]
        )
        adapter = MISPFeedAdapter(misp_client)

        candidates = adapter.search("stealc")

        self.assertEqual(["event-1", "event-2"], [c.external_id for c in candidates])
        self.assertEqual(["One", "Two"], [c.title for c in candidates])

    def test_enrich_returns_normalized_candidate(self):
        misp_client = SimpleNamespace(
            get_event=lambda event_id: {
                "uuid": "updated-event-id",
                "info": "Enriched event",
                "Attribute": [{"type": "url", "value": "https://example.com/a", "to_ids": True}],
            }
        )
        adapter = MISPFeedAdapter(misp_client)
        candidate = event_to_feed_candidate({"uuid": "event-1", "info": "Search event"})

        enriched = adapter.enrich(candidate)

        self.assertEqual("event-1", enriched.external_id)
        self.assertEqual("Enriched event", enriched.title)
        self.assertEqual("url", enriched.indicators[0]["type"])

    def test_enrich_skips_missing_or_failed_event(self):
        calls = []
        misp_client = SimpleNamespace(get_event=lambda event_id: calls.append(event_id))
        adapter = MISPFeedAdapter(misp_client)

        missing_id = event_to_feed_candidate({"info": "No ID"})
        self.assertIsNone(adapter.enrich(missing_id))
        self.assertEqual([], calls)

        failed = event_to_feed_candidate({"uuid": "event-1"})
        self.assertIsNone(adapter.enrich(failed))
        self.assertEqual(["event-1"], calls)

    def test_adapter_can_use_custom_source(self):
        source = FeedSource(
            name="MISP Customer A",
            source_type="customer_import",
            provider="MISP",
            default_confidence=75,
        )
        misp_client = SimpleNamespace(search_events=lambda query: [{"uuid": "event-1"}])
        adapter = MISPFeedAdapter(misp_client, source=source)

        candidate = adapter.search("ransomware")[0]

        self.assertEqual("misp:misp-customer-a", candidate.source.key)
        self.assertEqual("customer_import", candidate.source.source_type)


class MISPClientTests(unittest.TestCase):
    def test_event_records_extracts_common_misp_response_shapes(self):
        data = {
            "response": [
                {"Event": {"uuid": "event-1"}},
                {"Event": {"uuid": "event-2"}},
            ]
        }

        events = MISPClient.event_records(data)

        self.assertEqual(["event-1", "event-2"], [event["uuid"] for event in events])


if __name__ == "__main__":
    unittest.main()
