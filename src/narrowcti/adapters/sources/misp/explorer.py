"""Read-only, bounded MISP Source Explorer provider."""

from __future__ import annotations

from urllib.parse import quote

from narrowcti.adapters.sources.bounded_http import probe_status, request_json, validate_base_url
from narrowcti.adapters.sources.fingerprint import source_document_fingerprint
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


_MAX_INDICATORS = 100
_MAX_VALUE_LENGTH = 512


def _event(value):
    if isinstance(value, dict) and isinstance(value.get("Event"), dict):
        return value["Event"]
    return value if isinstance(value, dict) else {}


def _tag_values(value):
    event = _event(value)
    tags = event.get("Tag") or event.get("tags") or []
    result = []
    for tag in tags:
        name = tag if isinstance(tag, str) else tag.get("name") or tag.get("Name") if isinstance(tag, dict) else ""
        if name:
            result.append(str(name)[:128])
    return tuple(result[:50])


def _published(event):
    return str(event.get("date") or event.get("publish_timestamp") or "") or None


def _summary(value):
    event = _event(value)
    external_id = str(event.get("id") or event.get("uuid") or "")
    if not external_id:
        raise ExplorerError("invalid_provider_response", "The source provider returned an item without an identifier.")
    return ExplorerItemSummary(
        provider_key="misp",
        external_id=external_id[:256],
        title=str(event.get("info") or event.get("name") or external_id)[:512],
        published_at=_published(event),
        tlp=next((tag for tag in _tag_values(event) if tag.lower().startswith("tlp:")), None),
        tags=_tag_values(event),
    )


class MISPSourceExplorer:
    def __init__(
        self,
        base_url: str | None,
        api_key: str | None,
        *,
        verify_tls: bool = True,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        self._api_key = str(api_key or "").strip()
        self._verify_tls = bool(verify_tls)
        self._max_response_bytes = int(max_response_bytes)
        try:
            self._base_url = validate_base_url(base_url or "")
            endpoint_error = None
        except ValueError:
            self._base_url = ""
            endpoint_error = "endpoint_not_configured"
        self._unavailable_reason = endpoint_error or (None if self._api_key else "credential_missing")

    def descriptor(self):
        return ProviderDescriptor(
            key="misp",
            display_name="MISP",
            available=self._unavailable_reason is None,
            unavailable_reason=self._unavailable_reason,
            operations=(ProviderOperation.SEARCH, ProviderOperation.DETAIL),
            filters=(ProviderFilterDescriptor("tag", "Tag", multiple=True),),
        )

    def search(self, request: ExplorerSearchRequest) -> ExplorerSearchResult:
        self._ensure_available()
        payload: dict[str, object] = {
            "returnFormat": "json",
            "metadata": True,
            "includeEventTags": True,
            "searchall": request.query,
            "limit": request.limit + 1,
        }
        tags = request.filters.get("tag")
        if tags:
            payload["tags"] = list(tags) if isinstance(tags, tuple) else [tags]
        data = request_json(
            "POST",
            f"{self._base_url}/events/restSearch",
            headers=self._headers(),
            json_body=payload,
            verify_tls=self._verify_tls,
            max_response_bytes=self._max_response_bytes,
        )
        records = self._records(data)
        items = tuple(_summary(item) for item in records[:request.limit])
        return ExplorerSearchResult(
            provider_key="misp",
            items=items,
            truncated=len(records) > request.limit,
            has_more=len(records) > request.limit,
        )

    def detail(self, external_id: str) -> ExplorerItemDetail:
        self._ensure_available()
        data = request_json(
            "GET",
            f"{self._base_url}/events/view/{quote(external_id, safe='')}",
            headers=self._headers(),
            verify_tls=self._verify_tls,
            max_response_bytes=self._max_response_bytes,
        )
        event = _event(data)
        summary = _summary(event)
        raw_attributes = event.get("Attribute") or event.get("attributes") or []
        attributes = []
        if isinstance(raw_attributes, list):
            for item in raw_attributes[:_MAX_INDICATORS]:
                if not isinstance(item, dict):
                    continue
                item_type = str(item.get("type") or "")[:64]
                value = str(item.get("value") or "")[:_MAX_VALUE_LENGTH]
                if item_type and value:
                    attributes.append({"type": item_type, "value": value})
        fields = {
            "description": str(event.get("info") or "")[:4000],
            "date": str(event.get("date") or "") or None,
            "published": str(event.get("publish_timestamp") or "") or None,
            "threat_level_id": str(event.get("threat_level_id") or "") or None,
            "analysis": str(event.get("analysis") or "") or None,
            "tags": list(summary.tags),
            "attributes": attributes,
            "attributes_truncated": len(raw_attributes) > len(attributes) if isinstance(raw_attributes, list) else False,
        }
        fingerprint = source_document_fingerprint(event)
        return ExplorerItemDetail(
            summary=ExplorerItemSummary(**{**summary.__dict__, "revision_fingerprint": fingerprint}),
            fields=fields,
            provenance={"source": "misp", "external_id": summary.external_id, "fingerprint": fingerprint},
        )

    def probe_readiness(self) -> int:
        """Check the read-only MISP server-version endpoint; never read its body."""
        self._ensure_available()
        return probe_status(
            "GET",
            f"{self._base_url}/servers/getVersion",
            headers=self._headers(),
            verify_tls=self._verify_tls,
        )

    def _ensure_available(self):
        if self._unavailable_reason == "endpoint_not_configured":
            raise ExplorerError("provider_unavailable", "MISP is not configured.")
        if not self._api_key:
            raise ExplorerError("provider_unavailable", "MISP is not configured.")

    def _headers(self):
        return {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "NarrowCTI Community Source Explorer",
        }

    @staticmethod
    def _records(value):
        if isinstance(value, list):
            return value
        if not isinstance(value, dict):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid event data.")
        response = value.get("response")
        if isinstance(response, list):
            return [_event(item) for item in response if isinstance(item, dict)]
        if isinstance(value.get("Event"), dict):
            return [value["Event"]]
        if isinstance(response, dict):
            return MISPSourceExplorer._records(response)
        return []


__all__ = ["MISPSourceExplorer"]
