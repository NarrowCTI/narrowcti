"""Read-only, bounded MISP Source Explorer provider."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from urllib.parse import quote

from narrowcti.adapters.sources.bounded_http import (
    DEFAULT_TOTAL_TIMEOUT_SECONDS,
    probe_status,
    request_json,
    validate_base_url,
)
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
_ATTRIBUTE_FETCH_LIMIT = _MAX_INDICATORS + 1
_MAX_VALUE_LENGTH = 512
_MAX_TAG_CANDIDATES = 3
_MAX_UPSTREAM_REQUESTS = 3
_MAX_PROVIDER_RECORDS = 100
_SEARCH_DEADLINE_SECONDS = DEFAULT_TOTAL_TIMEOUT_SECONDS
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$"
)
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_MIN_BOUNDED_DETAIL_VERSION = (2, 5, 35)


def _event(value):
    if isinstance(value, dict) and isinstance(value.get("Event"), dict):
        return value["Event"]
    return value if isinstance(value, dict) else {}


def _invalid_provider_response():
    return ExplorerError("invalid_provider_response", "The source provider returned invalid event data.")


def _strict_event(value):
    if not isinstance(value, dict):
        raise _invalid_provider_response()
    event = value.get("Event")
    if event is None and isinstance(value.get("response"), dict):
        event = value["response"].get("Event")
    if not isinstance(event, dict):
        raise _invalid_provider_response()
    return event


def _identifier(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    identifier = str(value).strip()
    return identifier or None


def _count(value):
    if isinstance(value, bool):
        raise _invalid_provider_response()
    if isinstance(value, int):
        count = value
    elif isinstance(value, str) and value.isdecimal():
        count = int(value)
    else:
        raise _invalid_provider_response()
    if count < 0:
        raise _invalid_provider_response()
    return count


def _attributes_and_total(value):
    if not isinstance(value, dict):
        raise _invalid_provider_response()
    response = value.get("response")
    container = response if isinstance(response, dict) else value
    if "Attribute" in container:
        attributes = container["Attribute"]
    else:
        attributes = container.get("attributes")
    if not isinstance(attributes, list):
        raise _invalid_provider_response()
    total_value = value.get("total", container.get("total"))
    total = _count(total_value)
    if "total" in value and "total" in container and _count(value["total"]) != _count(container["total"]):
        raise _invalid_provider_response()
    return attributes, total


def _misp_version(value):
    if not isinstance(value, dict):
        return None
    version_value = value.get("version")
    if version_value is None and isinstance(value.get("Server"), dict):
        version_value = value["Server"].get("version")
    if not isinstance(version_value, str):
        return None
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)(?:[^0-9].*)?$", version_value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


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
        title=str(event.get("info") or event.get("name") or f"MISP Event {external_id}")[:512],
        published_at=_published(event),
        tlp=next((tag for tag in _tag_values(event) if tag.lower().startswith("tlp:")), None),
        tags=_tag_values(event),
    )


def _observable_kind(query: str) -> str | None:
    """Return a deterministic observable kind, or None for generic text."""
    try:
        parsed = ipaddress.ip_address(query)
    except ValueError:
        parsed = None
    if parsed is not None:
        return "ipv4" if parsed.version == 4 else "ipv6"
    if len(query) in _HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", query):
        return _HASH_LENGTHS[len(query)]
    if _DOMAIN_RE.fullmatch(query):
        return "domain"
    return None


class _SearchBudget:
    def __init__(
        self,
        *,
        deadline_seconds: float = _SEARCH_DEADLINE_SECONDS,
        max_requests: int = _MAX_UPSTREAM_REQUESTS,
    ) -> None:
        self.deadline = time.monotonic() + deadline_seconds
        self.requests = 0
        self.max_requests = max_requests

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ExplorerError("provider_timeout", "The source provider request timed out.", True)
        return remaining

    def consume(self) -> None:
        if self.requests >= self.max_requests:
            raise ExplorerError("provider_timeout", "The source provider search budget was exhausted.", True)
        self.requests += 1


@dataclass(frozen=True)
class _RecordBatch:
    records: list
    upstream_may_have_more: bool = False


@dataclass(frozen=True)
class _TagBatch:
    names: list[str]
    upstream_may_have_more: bool = False


class MISPSourceExplorer:
    def __init__(
        self,
        base_url: str | None,
        api_key: str | None,
        *,
        verify_tls: bool = True,
        max_response_bytes: int = 1_000_000,
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
        query = request.query.strip()
        budget = _SearchBudget()
        explicit_tags = request.filters.get("tag")
        tags = list(explicit_tags) if isinstance(explicit_tags, tuple) else ([explicit_tags] if explicit_tags else [])
        observable_kind = _observable_kind(query)
        if observable_kind is not None:
            data = self._request(
                budget,
                "/attributes/restSearch",
                {
                    "returnFormat": "json",
                    "metadata": True,
                    "value": query,
                    "limit": request.limit + 1,
                    **({"tags": tags} if tags else {}),
                },
            )
            batch = self._attribute_records(data, fetch_cap=request.limit + 1)
            records = batch.records
            upstream_may_have_more = batch.upstream_may_have_more
        elif tags:
            data = self._request(
                budget,
                "/events/restSearch",
                {
                    "returnFormat": "json",
                    "metadata": True,
                    "includeEventTags": True,
                    "eventinfo": query,
                    "tags": tags,
                    "limit": request.limit + 1,
                },
            )
            batch = self._records(data, fetch_cap=request.limit + 1)
            records = batch.records
            upstream_may_have_more = batch.upstream_may_have_more
        else:
            event_data = self._request(
                budget,
                "/events/index",
                {
                    "returnFormat": "json",
                    "metadata": True,
                    "includeEventTags": True,
                    "searcheventinfo": query,
                    "limit": request.limit + 1,
                    "page": 1,
                },
            )
            event_batch = self._records(event_data, fetch_cap=request.limit + 1)
            records = event_batch.records
            upstream_may_have_more = event_batch.upstream_may_have_more
            tag_data = self._request(budget, "/tags/search", {"tag": query})
            tag_batch = self._tag_names(tag_data)
            canonical_tags = tag_batch.names
            upstream_may_have_more = upstream_may_have_more or tag_batch.upstream_may_have_more
            if canonical_tags:
                tag_events = self._request(
                    budget,
                    "/events/restSearch",
                    {
                        "returnFormat": "json",
                        "metadata": True,
                        "includeEventTags": True,
                        "tags": canonical_tags,
                        "limit": request.limit + 1,
                    },
                )
                tag_event_batch = self._records(tag_events, fetch_cap=request.limit + 1)
                records.extend(tag_event_batch.records)
                upstream_may_have_more = upstream_may_have_more or tag_event_batch.upstream_may_have_more
        items, truncated = self._deduplicated_items(records, request.limit, upstream_may_have_more)
        return ExplorerSearchResult(
            provider_key="misp",
            items=items,
            truncated=truncated,
            has_more=truncated,
        )

    def _request(
        self,
        budget: _SearchBudget,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        method: str = "POST",
    ) -> object:
        budget.consume()
        remaining = budget.remaining()
        return request_json(
            method,
            f"{self._base_url}{path}",
            headers=self._headers(),
            json_body=payload,
            verify_tls=self._verify_tls,
            max_response_bytes=self._max_response_bytes,
            total_timeout=remaining,
            deadline=budget.deadline,
        )

    def detail(self, external_id: str) -> ExplorerItemDetail:
        self._ensure_available()
        budget = _SearchBudget(max_requests=2)
        encoded_id = quote(external_id, safe="")
        try:
            data = self._request(
                budget,
                f"/events/view2/{encoded_id}.json",
                method="GET",
            )
        except ExplorerError as exc:
            if exc.code != "source_not_found":
                raise
            self._distinguish_unsupported_detail_from_missing_event(budget, exc)
        event = _strict_event(data)
        event_id = _identifier(event.get("id"))
        event_uuid = _identifier(event.get("uuid"))
        if not event_id or external_id not in {event_id, event_uuid}:
            raise _invalid_provider_response()

        attributes_data = self._request(
            budget,
            f"/events/viewAttributes/{encoded_id}.json",
            {"page": 1, "limit": _ATTRIBUTE_FETCH_LIMIT},
        )
        raw_attributes, provider_total = _attributes_and_total(attributes_data)
        if len(raw_attributes) > _ATTRIBUTE_FETCH_LIMIT or provider_total < len(raw_attributes):
            raise _invalid_provider_response()
        shell_total = event.get("attribute_count")
        if shell_total is not None:
            # Event.attribute_count includes Object Attributes, while the
            # unflattened viewAttributes endpoint reports standalone ones.
            # Validate its shape, but do not compare these different counts.
            _count(shell_total)

        summary = _summary(event)
        attributes = []
        for item in raw_attributes:
            if not isinstance(item, dict):
                raise _invalid_provider_response()
            attribute_event_id = _identifier(item.get("event_id"))
            attribute_event_uuid = _identifier(item.get("event_uuid"))
            if (
                (attribute_event_id is not None and attribute_event_id != event_id)
                or (attribute_event_uuid is not None and event_uuid is not None and attribute_event_uuid != event_uuid)
                or (attribute_event_id is None and attribute_event_uuid is None)
            ):
                raise _invalid_provider_response()
            item_type = item.get("type")
            value = item.get("value")
            if not isinstance(item_type, str) or not item_type.strip() or not isinstance(value, str) or not value:
                raise _invalid_provider_response()
            if len(attributes) < _MAX_INDICATORS:
                attributes.append({"type": item_type[:64], "value": value[:_MAX_VALUE_LENGTH]})
        fields = {
            "description": str(event.get("info") or "")[:4000],
            "date": str(event.get("date") or "") or None,
            "published": str(event.get("publish_timestamp") or "") or None,
            "threat_level_id": str(event.get("threat_level_id") or "") or None,
            "analysis": str(event.get("analysis") or "") or None,
            "tags": list(summary.tags),
            "attributes": attributes,
            "attributes_truncated": provider_total > _MAX_INDICATORS,
        }
        return ExplorerItemDetail(
            summary=summary,
            fields=fields,
            provenance={"source": "misp", "external_id": summary.external_id},
        )

    def _distinguish_unsupported_detail_from_missing_event(self, budget, missing_event_error):
        try:
            version_data = self._request(
                budget,
                "/servers/getVersion",
                method="GET",
            )
        except ExplorerError:
            raise ExplorerError(
                "provider_unavailable",
                "MISP bounded Explorer detail is unavailable.",
                True,
            ) from None
        version = _misp_version(version_data)
        if version is None:
            raise _invalid_provider_response()
        if version < _MIN_BOUNDED_DETAIL_VERSION:
            raise ExplorerError(
                "provider_unavailable",
                "The configured MISP version does not support bounded Explorer detail.",
            )
        raise missing_event_error

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
    def _records(value, fetch_cap=None):
        if isinstance(value, list):
            return _RecordBatch(
                value[:_MAX_PROVIDER_RECORDS],
                len(value) >= _MAX_PROVIDER_RECORDS or (fetch_cap is not None and len(value) >= fetch_cap),
            )
        if not isinstance(value, dict):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid event data.")
        response = value.get("response")
        if isinstance(response, list):
            return _RecordBatch(
                [_event(item) for item in response[:_MAX_PROVIDER_RECORDS] if isinstance(item, dict)],
                len(response) >= _MAX_PROVIDER_RECORDS
                or (fetch_cap is not None and len(response) >= fetch_cap),
            )
        if isinstance(value.get("Event"), dict):
            return _RecordBatch([value["Event"]])
        if isinstance(response, dict):
            if isinstance(response.get("Event"), list):
                events = response["Event"]
                return _RecordBatch(
                    [item for item in events[:_MAX_PROVIDER_RECORDS] if isinstance(item, dict)],
                    len(events) >= _MAX_PROVIDER_RECORDS
                    or (fetch_cap is not None and len(events) >= fetch_cap),
                )
            return MISPSourceExplorer._records(response, fetch_cap=fetch_cap)
        return _RecordBatch([])

    @staticmethod
    def _attribute_records(value, fetch_cap=None):
        if not isinstance(value, dict):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid attribute data.")
        response = value.get("response")
        if isinstance(response, dict):
            attributes = response.get("Attribute") or response.get("attributes") or []
        else:
            attributes = value.get("Attribute") or value.get("attributes") or []
        if not isinstance(attributes, list):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid attribute data.")
        return _RecordBatch(
            attributes[:_MAX_PROVIDER_RECORDS],
            len(attributes) >= _MAX_PROVIDER_RECORDS
            or (fetch_cap is not None and len(attributes) >= fetch_cap),
        )

    @staticmethod
    def _tag_names(value):
        if isinstance(value, list):
            records = value
        elif isinstance(value, dict):
            response = value.get("response")
            if isinstance(response, list):
                records = response
            elif isinstance(response, dict):
                records = response.get("Tag") or response.get("tags") or []
            else:
                records = value.get("Tag") or value.get("tags") or []
        else:
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid tag data.")
        names = []
        upstream_may_have_more = len(records) > _MAX_TAG_CANDIDATES
        for record in records:
            if len(names) >= _MAX_TAG_CANDIDATES:
                break
            if not isinstance(record, dict):
                continue
            tag = record.get("Tag") or record.get("tag") or record
            if isinstance(tag, dict):
                name = tag.get("name") or tag.get("Name")
                if name and str(name) not in names:
                    names.append(str(name)[:128])
        return _TagBatch(names, upstream_may_have_more)

    @staticmethod
    def _deduplicated_items(records, limit, upstream_may_have_more=False):
        items = []
        seen = set()
        for record in records:
            event = _event(record)
            if not isinstance(record, dict):
                continue
            nested_event = record.get("Event") if isinstance(record.get("Event"), dict) else None
            external_id = str(
                record.get("event_id")
                or (nested_event or {}).get("id")
                or (record.get("id") if nested_event is None else None)
                or event.get("uuid")
                or record.get("uuid")
                or ""
            )
            if not external_id or external_id in seen:
                continue
            seen.add(external_id)
            if nested_event is not None or "event_id" not in record:
                items.append(_summary(event))
            else:
                projected = dict(record)
                projected["Event"] = {
                    **event,
                    "id": external_id,
                    "info": event.get("info") or f"MISP Event {external_id}",
                }
                items.append(_summary(projected))
        truncated = upstream_may_have_more or len(items) > limit
        return tuple(items[:limit]), truncated


__all__ = ["MISPSourceExplorer"]
