"""Read-only, bounded AlienVault OTX Source Explorer provider."""

from __future__ import annotations

from urllib.parse import quote

from narrowcti.adapters.sources.bounded_http import request_json
from narrowcti.adapters.sources.fingerprint import source_document_fingerprint
from narrowcti.ports.source_explorer import (
    ExplorerError,
    ExplorerItemDetail,
    ExplorerItemSummary,
    ExplorerSearchRequest,
    ExplorerSearchResult,
    ProviderDescriptor,
    ProviderOperation,
)


_SEARCH_URL = "https://otx.alienvault.com/api/v1/search/pulses"
_PULSE_BASE_URL = "https://otx.alienvault.com/api/v1/pulses"
_MAX_INDICATORS = 100
_MAX_VALUE_LENGTH = 512


def _summary(value):
    pulse_id = str(value.get("id") or "")
    if not pulse_id:
        raise ExplorerError("invalid_provider_response", "The source provider returned an item without an identifier.")
    raw_tags = value.get("tags") or value.get("industries") or []
    tags = (raw_tags,) if isinstance(raw_tags, str) else tuple(str(tag)[:128] for tag in raw_tags if tag)[:50]
    return ExplorerItemSummary(
        provider_key="otx",
        external_id=pulse_id[:256],
        title=str(value.get("name") or pulse_id)[:512],
        published_at=str(value.get("created") or "") or None,
        tags=tags,
    )


class OTXSourceExplorer:
    def __init__(self, api_key: str | None, *, max_response_bytes: int = 2_000_000) -> None:
        self._api_key = str(api_key or "").strip()
        self._max_response_bytes = int(max_response_bytes)

    def descriptor(self):
        return ProviderDescriptor(
            key="otx",
            display_name="AlienVault OTX",
            available=bool(self._api_key),
            unavailable_reason=None if self._api_key else "credential_missing",
            operations=(ProviderOperation.SEARCH, ProviderOperation.DETAIL),
        )

    def search(self, request: ExplorerSearchRequest) -> ExplorerSearchResult:
        self._ensure_available()
        data = request_json(
            "GET",
            _SEARCH_URL,
            headers=self._headers(),
            params={"q": request.query},
            verify_tls=True,
            max_response_bytes=self._max_response_bytes,
        )
        if not isinstance(data, dict):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid pulse data.")
        results = data.get("results")
        if not isinstance(results, list):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid pulse data.")
        items = tuple(_summary(item) for item in results[: request.limit + 1] if isinstance(item, dict))
        return ExplorerSearchResult(
            provider_key="otx",
            items=items[: request.limit],
            truncated=len(items) > request.limit,
            has_more=len(items) > request.limit,
            source_total=data.get("count") if isinstance(data.get("count"), int) else None,
        )

    def detail(self, external_id: str) -> ExplorerItemDetail:
        self._ensure_available()
        data = request_json(
            "GET",
            f"{_PULSE_BASE_URL}/{quote(external_id, safe='')}",
            headers=self._headers(),
            verify_tls=True,
            max_response_bytes=self._max_response_bytes,
        )
        if not isinstance(data, dict):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid pulse data.")
        summary = _summary(data)
        raw_indicators = data.get("indicators") or []
        indicators = []
        if isinstance(raw_indicators, list):
            for item in raw_indicators[:_MAX_INDICATORS]:
                if not isinstance(item, dict):
                    continue
                indicator_type = str(item.get("type") or "")[:64]
                value = str(item.get("indicator") or "")[:_MAX_VALUE_LENGTH]
                if indicator_type and value:
                    indicators.append({"type": indicator_type, "value": value})
        fingerprint = source_document_fingerprint(data)
        return ExplorerItemDetail(
            summary=ExplorerItemSummary(**{**summary.__dict__, "revision_fingerprint": fingerprint}),
            fields={
                "description": str(data.get("description") or "")[:4000],
                "created": str(data.get("created") or "") or None,
                "modified": str(data.get("modified") or "") or None,
                "tags": list(summary.tags),
                "indicators": indicators,
                "indicators_truncated": len(raw_indicators) > len(indicators) if isinstance(raw_indicators, list) else False,
            },
            provenance={"source": "otx", "external_id": summary.external_id, "fingerprint": fingerprint},
        )

    def _ensure_available(self):
        if not self._api_key:
            raise ExplorerError("provider_unavailable", "OTX is not configured.")

    def _headers(self):
        return {
            "X-OTX-API-KEY": self._api_key,
            "Accept": "application/json",
            "User-Agent": "NarrowCTI Community Source Explorer",
        }


__all__ = ["OTXSourceExplorer"]
