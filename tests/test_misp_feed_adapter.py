import unittest
from types import SimpleNamespace

from connectors.misp.client import MISPClient
from connectors.misp.feed_adapter import (
    MISPAdapterLimits,
    MISPFeedAdapter,
    MISP_SOURCE,
    attribute_to_indicators,
    event_attribute_count,
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

    def test_event_attribute_count_prefers_misp_metadata(self):
        event = {"attribute_count": "16922", "Attribute": [{"type": "domain"}]}

        self.assertEqual(16922, event_attribute_count(event))

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

    def test_attribute_to_indicators_maps_host_port_and_malware_sample(self):
        hostname_port = attribute_to_indicators(
            {"type": "hostname|port", "value": "c2.example.net|8443", "to_ids": True}
        )
        domain_port = attribute_to_indicators(
            {"type": "domain|port", "value": "198.51.100.10|443", "to_ids": True}
        )
        malware_sample = attribute_to_indicators(
            {
                "type": "malware-sample",
                "value": "payload.exe|" + "b" * 64,
                "to_ids": True,
            }
        )

        self.assertEqual("hostname", hostname_port[0]["type"])
        self.assertEqual("c2.example.net", hostname_port[0]["indicator"])
        self.assertEqual("ipv4", domain_port[0]["type"])
        self.assertEqual("198.51.100.10", domain_port[0]["indicator"])
        self.assertEqual("filehash-sha256", malware_sample[0]["type"])
        self.assertEqual("b" * 64, malware_sample[0]["indicator"])

    def test_adapter_matches_feed_adapter_protocol(self):
        adapter = MISPFeedAdapter(misp_client=SimpleNamespace())

        self.assertIsInstance(adapter, FeedAdapter)

    def test_search_uses_metadata_and_guardrail_limits(self):
        calls = []

        def search_events(query, limit=None, metadata=False, filters=None):
            calls.append(
                {
                    "query": query,
                    "limit": limit,
                    "metadata": metadata,
                    "filters": filters,
                }
            )
            return [
                {"uuid": "event-1", "info": "One", "attribute_count": 1},
                {"uuid": "event-2", "info": "Two", "attribute_count": 1},
                {"uuid": "event-3", "info": "Three", "attribute_count": 1},
            ]

        misp_client = SimpleNamespace(search_events=search_events)
        adapter = MISPFeedAdapter(
            misp_client,
            limits=MISPAdapterLimits(max_events_per_run=2, max_attributes_per_event=10),
            search_filters={"from": "2026-01-01", "tags": ["tlp:green"]},
        )

        candidates = adapter.search("stealc")

        self.assertEqual(
            [
                {
                    "query": "stealc",
                    "limit": 2,
                    "metadata": True,
                    "filters": {"from": "2026-01-01", "tags": ["tlp:green"]},
                }
            ],
            calls,
        )
        self.assertEqual(["event-1", "event-2"], [c.external_id for c in candidates])

    def test_search_skips_oversized_metadata_event_by_default(self):
        logs = []
        misp_client = SimpleNamespace(
            search_events=lambda query, limit=None, metadata=False, filters=None: [
                {"uuid": "big-event", "info": "Big", "attribute_count": 16922},
                {"uuid": "small-event", "info": "Small", "attribute_count": 10},
            ]
        )
        adapter = MISPFeedAdapter(
            misp_client,
            limits=MISPAdapterLimits(max_events_per_run=10, max_attributes_per_event=1000),
            logger=logs.append,
        )

        candidates = adapter.search("tlp:green")

        self.assertEqual(["small-event"], [c.external_id for c in candidates])
        self.assertEqual(2, adapter.last_search_available)
        self.assertEqual(1, adapter.last_search_skipped)
        self.assertIn("big-event", logs[0])

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

    def test_enrich_skips_oversized_event_by_default(self):
        misp_client = SimpleNamespace(
            get_event=lambda event_id: {
                "uuid": event_id,
                "info": "Oversized event",
                "attribute_count": 3,
                "Attribute": [
                    {"type": "domain", "value": "one.example", "to_ids": True},
                    {"type": "domain", "value": "two.example", "to_ids": True},
                    {"type": "domain", "value": "three.example", "to_ids": True},
                ],
            }
        )
        adapter = MISPFeedAdapter(
            misp_client,
            limits=MISPAdapterLimits(max_events_per_run=10, max_attributes_per_event=2),
        )
        candidate = event_to_feed_candidate({"uuid": "event-1", "info": "Search event"})

        self.assertIsNone(adapter.enrich(candidate))

    def test_enrich_can_truncate_oversized_event_when_configured(self):
        misp_client = SimpleNamespace(
            get_event=lambda event_id: {
                "uuid": event_id,
                "info": "Truncated event",
                "attribute_count": 3,
                "Attribute": [
                    {"type": "domain", "value": "one.example", "to_ids": True},
                    {"type": "domain", "value": "two.example", "to_ids": True},
                    {"type": "domain", "value": "three.example", "to_ids": True},
                ],
            }
        )
        adapter = MISPFeedAdapter(
            misp_client,
            limits=MISPAdapterLimits(
                max_events_per_run=10,
                max_attributes_per_event=2,
                oversized_event_action="truncate",
            ),
        )
        candidate = event_to_feed_candidate({"uuid": "event-1", "info": "Search event"})

        enriched = adapter.enrich(candidate)

        self.assertEqual(
            ["one.example", "two.example"],
            [ioc["indicator"] for ioc in enriched.indicators],
        )
        self.assertTrue(enriched.raw["narrowcti_controls"]["oversized"])
        self.assertEqual("truncate", enriched.raw["narrowcti_controls"]["oversized_event_action"])

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
        misp_client = SimpleNamespace(
            search_events=lambda query, limit=None, metadata=False, filters=None: [{"uuid": "event-1"}]
        )
        adapter = MISPFeedAdapter(misp_client, source=source)

        candidate = adapter.search("ransomware")[0]

        self.assertEqual("misp:misp-customer-a", candidate.source.key)
        self.assertEqual("customer_import", candidate.source.source_type)

    def test_limits_validate_guardrail_values(self):
        with self.assertRaises(ValueError):
            MISPAdapterLimits(max_events_per_run=0)
        with self.assertRaises(ValueError):
            MISPAdapterLimits(max_attributes_per_event=0)
        with self.assertRaises(ValueError):
            MISPAdapterLimits(oversized_event_action="import")


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

    def test_search_events_omits_searchall_for_backfill_wildcard(self):
        calls = []

        def request_json(method, path, payload=None, timeout_seconds=30):
            calls.append({"method": method, "path": path, "payload": payload})
            return {"response": [{"Event": {"uuid": "event-1"}}]}

        client = MISPClient("http://misp.local", "key")
        client.request_json = request_json

        events = client.search_events("*", limit=1, metadata=True, filters={"tags": ["tlp:green"]})

        self.assertEqual([{"uuid": "event-1"}], events)
        self.assertNotIn("searchall", calls[0]["payload"])
        self.assertEqual(["tlp:green"], calls[0]["payload"]["tags"])

    def test_search_events_sends_metadata_and_limit_payload(self):
        calls = []
        client = MISPClient("http://misp.local", "key")

        def request_json(method, path, payload=None, timeout_seconds=30):
            calls.append(
                {
                    "method": method,
                    "path": path,
                    "payload": payload,
                    "timeout_seconds": timeout_seconds,
                }
            )
            return {"response": [{"Event": {"uuid": "event-1"}}]}

        client.request_json = request_json

        events = client.search_events(
            "stealc",
            limit=5,
            metadata=True,
            filters={"from": "2026-01-01", "tags": ["tlp:green"], "published": True},
        )

        self.assertEqual([{"uuid": "event-1"}], events)
        self.assertEqual("POST", calls[0]["method"])
        self.assertEqual("/events/restSearch", calls[0]["path"])
        self.assertEqual("stealc", calls[0]["payload"]["searchall"])
        self.assertEqual(5, calls[0]["payload"]["limit"])
        self.assertTrue(calls[0]["payload"]["metadata"])
        self.assertEqual("2026-01-01", calls[0]["payload"]["from"])
        self.assertEqual(["tlp:green"], calls[0]["payload"]["tags"])
        self.assertTrue(calls[0]["payload"]["published"])


if __name__ == "__main__":
    unittest.main()
