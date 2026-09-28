"""Contracts for bounded Source Explorer dispatch."""

from __future__ import annotations

import unittest

from narrowcti.application.source_explorer import SourceExplorerService
from narrowcti.ports.source_explorer import (
    ExplorerError,
    ExplorerItemDetail,
    ExplorerItemSummary,
    ExplorerSearchRequest,
    ExplorerSearchResult,
    ProviderDescriptor,
    ProviderFilterDescriptor,
    ProviderOperation,
)


class FakeProvider:
    def __init__(self, *, available: bool = True, operations=None) -> None:
        self._descriptor = ProviderDescriptor(
            key="misp",
            display_name="MISP",
            available=available,
            unavailable_reason=None if available else "credential_missing",
            operations=tuple(operations or (ProviderOperation.SEARCH, ProviderOperation.DETAIL)),
            filters=(ProviderFilterDescriptor("tag", "Tag", multiple=True),),
        )
        self.search_request = None
        self.detail_identifier = None

    def descriptor(self):
        return self._descriptor

    def search(self, request):
        self.search_request = request
        item = ExplorerItemSummary(provider_key="misp", external_id="42", title="Example")
        return ExplorerSearchResult(provider_key="misp", items=(item,))

    def detail(self, external_id):
        self.detail_identifier = external_id
        summary = ExplorerItemSummary(provider_key="misp", external_id=external_id, title="Example")
        return ExplorerItemDetail(summary=summary, fields={}, provenance={})


class SourceExplorerServiceTests(unittest.TestCase):
    def test_provider_descriptors_are_aggregated_in_stable_order(self):
        first = FakeProvider()
        second = FakeProvider()
        second._descriptor = ProviderDescriptor("otx", "OTX", False)

        service = SourceExplorerService((second, first))

        self.assertEqual([item.key for item in service.providers()], ["misp", "otx"])

    def test_duplicate_or_empty_provider_keys_are_rejected(self):
        first = FakeProvider()
        duplicate = FakeProvider()
        with self.assertRaisesRegex(ValueError, "unique and non-empty"):
            SourceExplorerService((first, duplicate))

        empty = FakeProvider()
        empty._descriptor = ProviderDescriptor("", "Invalid", True)
        with self.assertRaisesRegex(ValueError, "unique and non-empty"):
            SourceExplorerService((empty,))

    def test_search_normalizes_and_forwards_only_declared_filters(self):
        provider = FakeProvider()
        service = SourceExplorerService((provider,))

        result = service.search(ExplorerSearchRequest("misp", "  malware  ", {"tag": (" apt ",)}))

        self.assertEqual(result.items[0].external_id, "42")
        self.assertEqual(provider.search_request.query, "malware")
        self.assertEqual(provider.search_request.filters["tag"], ("apt",))

    def test_unknown_unavailable_and_unsupported_provider_operations_fail_safely(self):
        unavailable = FakeProvider(available=False)
        service = SourceExplorerService((unavailable,))
        with self.assertRaisesRegex(ExplorerError, "unavailable") as caught:
            service.search(ExplorerSearchRequest("misp", "malware"))
        self.assertEqual(caught.exception.code, "provider_unavailable")

        unsupported = FakeProvider(operations=(ProviderOperation.DETAIL,))
        service = SourceExplorerService((unsupported,))
        with self.assertRaisesRegex(ExplorerError, "not supported") as caught:
            service.search(ExplorerSearchRequest("misp", "malware"))
        self.assertEqual(caught.exception.code, "operation_unsupported")

        with self.assertRaisesRegex(ExplorerError, "not available") as caught:
            service.detail("unknown", "42")
        self.assertEqual(caught.exception.code, "provider_unknown")

    def test_invalid_search_inputs_are_rejected(self):
        service = SourceExplorerService((FakeProvider(),))
        invalid_requests = (
            ExplorerSearchRequest("misp", " "),
            ExplorerSearchRequest("misp", "x" * 257),
            ExplorerSearchRequest("misp", "x", limit=11),
            ExplorerSearchRequest("misp", "x", {"unlisted": "value"}),
            ExplorerSearchRequest("misp", "x", {"tag": tuple(str(i) for i in range(11))}),
            ExplorerSearchRequest("misp", "x", {"tag": " "}),
        )
        for request in invalid_requests:
            with self.subTest(request=request):
                with self.assertRaises(ExplorerError) as caught:
                    service.search(request)
                self.assertEqual(caught.exception.code, "invalid_request")

    def test_detail_identifier_is_validated_before_provider_call(self):
        provider = FakeProvider()
        service = SourceExplorerService((provider,))

        with self.assertRaises(ExplorerError) as caught:
            service.detail("misp", "bad\nidentifier")

        self.assertEqual(caught.exception.code, "invalid_request")
        self.assertIsNone(provider.detail_identifier)


if __name__ == "__main__":
    unittest.main()
