"""Contracts for concrete read-only MISP and OTX explorer providers."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from narrowcti.adapters.sources.misp.explorer import MISPSourceExplorer, _observable_kind
from narrowcti.adapters.sources.otx.explorer import OTXSourceExplorer
from narrowcti.ports.source_explorer import ExplorerError, ExplorerSearchRequest


class SourceExplorerProviderTests(unittest.TestCase):
    def test_misp_intent_classifier_is_deterministic_and_conservative(self):
        cases = (
            ("203.0.113.7", "ipv4"),
            ("2001:db8::7", "ipv6"),
            ("example.org", "domain"),
            ("a" * 32, "md5"),
            ("b" * 40, "sha1"),
            ("c" * 64, "sha256"),
            ("CVE-2026-1234", None),
            ("Lazarus Group", None),
        )
        for query, expected in cases:
            with self.subTest(query=query):
                self.assertEqual(expected, _observable_kind(query))

    def test_missing_credentials_disable_only_the_provider(self):
        misp = MISPSourceExplorer("https://misp.example", None)
        otx = OTXSourceExplorer(None)
        self.assertFalse(misp.descriptor().available)
        self.assertEqual(misp.descriptor().unavailable_reason, "credential_missing")
        self.assertFalse(otx.descriptor().available)
        self.assertEqual(otx.descriptor().unavailable_reason, "credential_missing")

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_search_uses_configured_endpoint_filters_and_allowlisted_summary(self, request):
        request.return_value = {
            "response": [
                {"Event": {"id": "42", "info": "Lazarus", "date": "2026-09-01", "Tag": [{"name": "tlp:amber"}], "secret": "not projected"}},
                {"Event": {"id": "43", "info": "Second"}},
            ]
        }
        provider = MISPSourceExplorer("https://misp.example/api", "synthetic-misp-key")

        result = provider.search(ExplorerSearchRequest("misp", "lazarus", {"tag": ("apt",)}, limit=1))

        self.assertEqual(result.items[0].title, "Lazarus")
        self.assertEqual(result.items[0].tlp, "tlp:amber")
        self.assertTrue(result.truncated)
        args = request.call_args.kwargs
        self.assertEqual(request.call_args.args[1], "https://misp.example/api/events/restSearch")
        self.assertEqual(args["json_body"]["tags"], ["apt"])
        self.assertEqual(args["json_body"]["limit"], 2)
        self.assertEqual(args["headers"]["Authorization"], "synthetic-misp-key")
        self.assertNotIn("secret", result.items[0].__repr__())

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_observable_uses_attribute_value_and_keeps_event_identity(self, request):
        request.return_value = {
            "response": {
                "Attribute": [
                    {"id": "a-1", "event_id": "42", "value": "203.0.113.7"},
                    {"id": "a-2", "event_id": "42", "value": "203.0.113.7"},
                ]
            }
        }
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.search(ExplorerSearchRequest("misp", "203.0.113.7", limit=10))

        self.assertEqual(("42",), tuple(item.external_id for item in result.items))
        self.assertEqual("MISP Event 42", result.items[0].title)
        self.assertEqual("https://misp.example/api/attributes/restSearch", request.call_args.args[1])
        payload = request.call_args.kwargs["json_body"]
        self.assertEqual("203.0.113.7", payload["value"])
        self.assertNotIn("searchall", payload)
        self.assertNotIn("searchattribute", payload)
        self.assertFalse(result.truncated)
        self.assertEqual(result.truncated, result.has_more)

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_observable_preserves_explicit_tag_filter_provider_side(self, request):
        request.return_value = {
            "response": {"Attribute": [{"event_id": "42", "value": "203.0.113.7"}]}
        }
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.search(ExplorerSearchRequest("misp", "203.0.113.7", {"tag": ("apt",)}))

        self.assertEqual(("42",), tuple(item.external_id for item in result.items))
        self.assertEqual(1, request.call_count)
        payload = request.call_args.kwargs["json_body"]
        self.assertEqual("203.0.113.7", payload["value"])
        self.assertEqual(["apt"], payload["tags"])

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_hash_and_generic_text_choose_distinct_bounded_routes(self, request):
        request.side_effect = [
            {"response": {"Attribute": [{"event_id": "hash-event", "Event": {"id": "hash-event", "info": "Hash event"}}]}},
            {"response": [{"Event": {"id": "event-1", "info": "CVE-2026-1234"}}]},
            {"response": []},
        ]
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        hash_result = provider.search(ExplorerSearchRequest("misp", "a" * 64))
        generic_result = provider.search(ExplorerSearchRequest("misp", "CVE-2026-1234"))

        self.assertEqual("hash-event", hash_result.items[0].external_id)
        self.assertEqual("event-1", generic_result.items[0].external_id)
        self.assertEqual("https://misp.example/api/attributes/restSearch", request.call_args_list[0].args[1])
        self.assertEqual("https://misp.example/api/events/index", request.call_args_list[1].args[1])
        self.assertEqual("CVE-2026-1234", request.call_args_list[1].kwargs["json_body"]["searcheventinfo"])
        self.assertEqual("https://misp.example/api/tags/search", request.call_args_list[2].args[1])
        self.assertNotIn("searchall", repr(request.call_args_list))

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_generic_text_resolves_canonical_tag_and_event_results(self, request):
        request.side_effect = [
            {"response": [{"Event": {"id": "9", "info": "APT Example"}}]},
            [{"Tag": {"name": "misp-galaxy:threat-actor=APT-Example"}}],
            {"response": [{"Event": {"id": "9", "info": "APT Example"}}]},
        ]
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.search(ExplorerSearchRequest("misp", "APT Example", limit=10))

        self.assertEqual(("9",), tuple(item.external_id for item in result.items))
        self.assertFalse(result.truncated)
        self.assertEqual(result.truncated, result.has_more)
        tag_payload = request.call_args_list[2].kwargs["json_body"]
        self.assertEqual(["misp-galaxy:threat-actor=APT-Example"], tag_payload["tags"])
        self.assertNotIn("searchall", repr(request.call_args_list))

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_explicit_tag_filter_stays_provider_side_without_fanout(self, request):
        request.return_value = {"response": [{"Event": {"id": "7", "info": "Tagged event"}}]}
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.search(ExplorerSearchRequest("misp", "Tagged", {"tag": ("apt",)}, limit=10))

        self.assertEqual(("7",), tuple(item.external_id for item in result.items))
        self.assertEqual(1, request.call_count)
        payload = request.call_args.kwargs["json_body"]
        self.assertEqual("Tagged", payload["eventinfo"])
        self.assertEqual(["apt"], payload["tags"])

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_attribute_fetch_cap_survives_event_deduplication(self, request):
        request.return_value = {
            "response": {
                "Attribute": [
                    {"id": str(index), "event_id": "42", "value": "203.0.113.7"}
                    for index in range(11)
                ]
            }
        }
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.search(ExplorerSearchRequest("misp", "203.0.113.7", limit=10))

        self.assertEqual(("42",), tuple(item.external_id for item in result.items))
        self.assertTrue(result.truncated)
        self.assertEqual(result.truncated, result.has_more)

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_unique_result_cap_is_conservative(self, request):
        request.return_value = {
            "response": [
                {"Event": {"id": str(index), "info": f"Tagged {index}"}}
                for index in range(11)
            ]
        }
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.search(ExplorerSearchRequest("misp", "Tagged", {"tag": ("apt",)}, limit=10))

        self.assertEqual(10, len(result.items))
        self.assertTrue(result.truncated)
        self.assertEqual(result.truncated, result.has_more)

    @patch("narrowcti.adapters.sources.misp.explorer.time.monotonic", side_effect=[0.0, 16.0])
    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_aggregate_budget_does_not_restart_per_request(self, request, _clock):
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        with self.assertRaises(ExplorerError) as raised:
            provider.search(ExplorerSearchRequest("misp", "generic text"))

        self.assertEqual("provider_timeout", raised.exception.code)
        request.assert_not_called()

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_detail_uses_two_bounded_endpoints_and_has_no_revision_fingerprint(self, request):
        request.side_effect = [
            {
                "Event": {
                    "id": "42",
                    "uuid": "event-uuid-42",
                    "attribute_count": "1",
                    "info": "Incident",
                    "date": "2026-09-01",
                    "publish_timestamp": "2026-09-02",
                    "Tag": [{"name": "tlp:green"}],
                    "secret": "not projected",
                }
            },
            {
                "response": {
                    "Attribute": [
                        {
                            "event_id": "42",
                            "event_uuid": "event-uuid-42",
                            "type": "domain",
                            "value": "bad.example",
                        }
                    ],
                    "total": 1,
                }
            },
        ]
        provider = MISPSourceExplorer("https://misp.example/api", "key")

        result = provider.detail("42")

        self.assertEqual(2, request.call_count)
        self.assertEqual("GET", request.call_args_list[0].args[0])
        self.assertEqual("https://misp.example/api/events/view2/42.json", request.call_args_list[0].args[1])
        self.assertEqual("POST", request.call_args_list[1].args[0])
        self.assertEqual("https://misp.example/api/events/viewAttributes/42.json", request.call_args_list[1].args[1])
        self.assertEqual({"page": 1, "limit": 101}, request.call_args_list[1].kwargs["json_body"])
        self.assertEqual(1_000_000, request.call_args_list[0].kwargs["max_response_bytes"])
        self.assertEqual(1_000_000, request.call_args_list[1].kwargs["max_response_bytes"])
        self.assertEqual(
            request.call_args_list[0].kwargs["deadline"],
            request.call_args_list[1].kwargs["deadline"],
        )
        self.assertTrue(request.call_args_list[0].kwargs["verify_tls"])
        self.assertEqual("42", result.summary.external_id)
        self.assertEqual(("tlp:green",), result.summary.tags)
        self.assertEqual(result.fields["attributes"], [{"type": "domain", "value": "bad.example"}])
        self.assertFalse(result.fields["attributes_truncated"])
        self.assertIsNone(result.summary.revision_fingerprint)
        self.assertNotIn("fingerprint", result.provenance)
        self.assertNotIn("secret", result.fields)
        self.assertNotIn("/events/view/", repr(request.call_args_list))

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_detail_renders_at_most_100_and_uses_provider_total_for_truncation(self, request):
        attributes = [
            {"event_id": "42", "type": "domain", "value": f"item-{index}.example"}
            for index in range(101)
        ]
        request.side_effect = [
            {"Event": {"id": "42", "uuid": "event-uuid-42", "attribute_count": 120, "info": "Incident"}},
            {"Attribute": attributes, "total": 120},
        ]
        result = MISPSourceExplorer("https://misp.example", "key").detail("42")
        self.assertEqual(100, len(result.fields["attributes"]))
        self.assertTrue(result.fields["attributes_truncated"])

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_detail_total_of_100_is_not_truncated(self, request):
        attributes = [
            {"event_id": "42", "type": "domain", "value": f"item-{index}.example"}
            for index in range(100)
        ]
        request.side_effect = [
            {"Event": {"id": "42", "attribute_count": "100", "info": "Incident"}},
            {"Attribute": attributes, "total": "100"},
        ]
        result = MISPSourceExplorer("https://misp.example", "key").detail("42")
        self.assertEqual(100, len(result.fields["attributes"]))
        self.assertFalse(result.fields["attributes_truncated"])

    @patch("narrowcti.adapters.sources.misp.explorer.time.monotonic", side_effect=[0.0, 1.0, 3.0])
    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_detail_propagates_one_aggregate_deadline(self, request, _clock):
        request.side_effect = [
            {"Event": {"id": "42", "attribute_count": 0, "info": "Incident"}},
            {"Attribute": [], "total": 0},
        ]

        MISPSourceExplorer("https://misp.example", "key").detail("42")

        first, second = request.call_args_list
        self.assertEqual(first.kwargs["deadline"], second.kwargs["deadline"])
        self.assertLess(second.kwargs["total_timeout"], first.kwargs["total_timeout"])

    def test_misp_detail_rejects_mismatched_event_identity_and_invalid_totals(self):
        cases = (
            (
                {"Event": {"id": "43", "attribute_count": 0, "info": "Wrong event"}},
                {"Attribute": [], "total": 0},
            ),
            (
                {"Event": {"id": "42", "uuid": "uuid-42", "attribute_count": 1, "info": "Incident"}},
                {"Attribute": [{"event_id": "43", "type": "domain", "value": "bad.example"}], "total": 1},
            ),
            (
                {"Event": {"id": "42", "uuid": "uuid-42", "attribute_count": 1, "info": "Incident"}},
                {
                    "Attribute": [
                        {
                            "event_id": "42",
                            "event_uuid": "uuid-other",
                            "type": "domain",
                            "value": "bad.example",
                        }
                    ],
                    "total": 1,
                },
            ),
            (
                {"Event": {"id": "42", "attribute_count": 2, "info": "Incident"}},
                {"Attribute": [{"event_id": "42", "type": "domain", "value": "bad.example"}], "total": "unknown"},
            ),
            (
                {"Event": {"id": "42", "attribute_count": 0, "info": "Incident"}},
                {"Attribute": [], "total": -1},
            ),
        )
        for shell, attributes in cases:
            with self.subTest(shell=shell, attributes=attributes):
                with patch(
                    "narrowcti.adapters.sources.misp.explorer.request_json",
                    side_effect=[shell, attributes],
                ):
                    with self.assertRaises(ExplorerError) as raised:
                        MISPSourceExplorer("https://misp.example", "key").detail("42")
                self.assertEqual("invalid_provider_response", raised.exception.code)

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_detail_404_checks_version_only_to_distinguish_old_server(self, request):
        request.side_effect = [
            ExplorerError("source_not_found", "missing"),
            {"version": "2.5.34"},
        ]
        with self.assertRaises(ExplorerError) as raised:
            MISPSourceExplorer("https://misp.example", "key").detail("42")
        self.assertEqual("provider_unavailable", raised.exception.code)
        self.assertEqual(2, request.call_count)
        self.assertEqual("https://misp.example/servers/getVersion", request.call_args_list[1].args[1])

    @patch("narrowcti.adapters.sources.misp.explorer.request_json")
    def test_misp_supported_server_keeps_missing_event_not_found(self, request):
        request.side_effect = [
            ExplorerError("source_not_found", "missing"),
            {"version": "2.5.35"},
        ]
        with self.assertRaises(ExplorerError) as raised:
            MISPSourceExplorer("https://misp.example", "key").detail("42")
        self.assertEqual("source_not_found", raised.exception.code)
        self.assertEqual(2, request.call_count)

    @patch("narrowcti.adapters.sources.otx.explorer.request_json")
    def test_otx_search_is_fixed_endpoint_and_returns_only_summary_fields(self, request):
        request.return_value = {"count": 20, "results": [{"id": "pulse-1", "name": "Campaign", "tags": ["malware"], "secret": "no"}]}
        provider = OTXSourceExplorer("synthetic-otx-key")

        result = provider.search(ExplorerSearchRequest("otx", "campaign", limit=1))

        self.assertEqual(result.items[0].external_id, "pulse-1")
        self.assertEqual(result.source_total, 20)
        self.assertNotIn("secret", repr(result.items[0]))
        self.assertEqual(request.call_args.args[1], "https://otx.alienvault.com/api/v1/search/pulses")
        self.assertEqual(request.call_args.kwargs["params"], {"q": "campaign"})
        self.assertTrue(request.call_args.kwargs["verify_tls"])

    @patch("narrowcti.adapters.sources.otx.explorer.request_json")
    def test_otx_detail_fingerprint_is_bound_to_refetched_provider_payload(self, request):
        request.return_value = {
            "id": "pulse-1",
            "name": "Campaign",
            "description": "Details",
            "indicators": [{"type": "domain", "indicator": "bad.example"}],
            "internal": "not projected",
        }
        provider = OTXSourceExplorer("key")

        result = provider.detail("pulse-1")

        self.assertEqual(result.fields["indicators"], [{"type": "domain", "value": "bad.example"}])
        self.assertNotIn("internal", result.fields)
        self.assertEqual(result.summary.revision_fingerprint, result.provenance["fingerprint"])
        self.assertEqual(request.call_args.args[1], "https://otx.alienvault.com/api/v1/pulses/pulse-1")


if __name__ == "__main__":
    unittest.main()
