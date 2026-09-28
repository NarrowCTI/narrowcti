"""Contracts for concrete read-only MISP and OTX explorer providers."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from narrowcti.adapters.sources.misp.explorer import MISPSourceExplorer
from narrowcti.adapters.sources.otx.explorer import OTXSourceExplorer
from narrowcti.ports.source_explorer import ExplorerSearchRequest


class SourceExplorerProviderTests(unittest.TestCase):
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
    def test_misp_detail_returns_bounded_projection_and_fingerprint(self, request):
        request.return_value = {
            "Event": {
                "id": "42",
                "info": "Incident",
                "date": "2026-09-01",
                "Tag": [{"name": "tlp:green"}],
                "Attribute": [{"type": "domain", "value": "bad.example"}],
                "secret": "not projected",
            }
        }
        provider = MISPSourceExplorer("https://misp.example", "key")

        result = provider.detail("42/../../../secret")

        self.assertEqual(result.fields["attributes"], [{"type": "domain", "value": "bad.example"}])
        self.assertNotIn("secret", result.fields)
        self.assertEqual(result.summary.revision_fingerprint, result.provenance["fingerprint"])
        self.assertIn("%2F", request.call_args.args[1])
        self.assertTrue(request.call_args.kwargs["verify_tls"])

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
