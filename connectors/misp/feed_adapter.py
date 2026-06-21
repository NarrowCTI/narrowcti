import ipaddress
from datetime import datetime, timezone

from core.feed_contract import FeedCandidate, FeedSource


MISP_SOURCE = FeedSource(
    name="MISP",
    source_type="external_import",
    provider="MISP",
    default_confidence=60,
)

MISP_TYPE_MAP = {
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "uri": "url",
    "email": "email",
    "email-src": "email",
    "email-dst": "email",
    "target-email": "email",
    "whois-registrant-email": "email",
    "md5": "filehash-md5",
    "sha1": "filehash-sha1",
    "sha256": "filehash-sha256",
}

HASH_COMPOSITE_TYPES = {
    "filename|md5": "filehash-md5",
    "filename|sha1": "filehash-sha1",
    "filename|sha256": "filehash-sha256",
}

IP_PORT_TYPES = {
    "ip-src|port",
    "ip-dst|port",
    "ip|port",
}


def unwrap_event(record):
    if isinstance(record, dict) and isinstance(record.get("Event"), dict):
        return record["Event"]
    return record if isinstance(record, dict) else {}


def tag_name(tag):
    if isinstance(tag, str):
        return tag
    if isinstance(tag, dict):
        return tag.get("name") or tag.get("Name") or ""
    return ""


def event_tags(event):
    tags = [tag_name(tag) for tag in event.get("Tag", [])]
    return [tag for tag in tags if tag]


def attribute_tags(attribute):
    tags = [tag_name(tag) for tag in attribute.get("Tag", [])]
    return [tag for tag in tags if tag]


def event_created(event):
    if event.get("date"):
        return event["date"]

    timestamp = event.get("timestamp") or event.get("publish_timestamp")
    if not timestamp:
        return None

    try:
        dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None

    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def org_name(org):
    if isinstance(org, dict):
        return org.get("name") or org.get("Name") or org.get("uuid") or ""
    return ""


def original_source(event):
    return (
        event.get("source")
        or event.get("Source")
        or org_name(event.get("Orgc"))
        or org_name(event.get("Org"))
        or ""
    )


def event_attributes(event):
    attributes = list(event.get("Attribute") or [])

    for misp_object in event.get("Object") or []:
        attributes.extend(misp_object.get("Attribute") or [])

    return attributes


def split_attribute_values(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split("\n") if item.strip()]


def ip_indicator_type(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return "ipv4" if ip.version == 4 else "ipv6"


def indicator(indicator_type, value, attribute):
    return {
        "type": indicator_type,
        "indicator": value,
        "misp_type": attribute.get("type", ""),
        "misp_category": attribute.get("category", ""),
        "misp_uuid": attribute.get("uuid", ""),
        "first_seen": attribute.get("first_seen", ""),
        "last_seen": attribute.get("last_seen", ""),
        "tags": attribute_tags(attribute),
    }


def attribute_to_indicators(attribute):
    if isinstance(attribute, dict) and isinstance(attribute.get("Attribute"), dict):
        attribute = attribute["Attribute"]

    if not isinstance(attribute, dict):
        return []

    if attribute.get("deleted") is True or attribute.get("to_ids") is False:
        return []

    attribute_type = str(attribute.get("type", "")).lower()
    values = split_attribute_values(attribute.get("value"))
    indicators = []

    for value in values:
        if attribute_type in ("ip-src", "ip-dst", "ip"):
            normalized_type = ip_indicator_type(value)
            if normalized_type:
                indicators.append(indicator(normalized_type, value, attribute))
            continue

        if attribute_type in IP_PORT_TYPES:
            parts = [part.strip() for part in value.rsplit("|", 1)]
            if len(parts) == 2:
                normalized_type = ip_indicator_type(parts[0])
                if normalized_type:
                    indicators.append(indicator(normalized_type, parts[0], attribute))
            continue

        if attribute_type == "domain|ip":
            parts = [part.strip() for part in value.split("|", 1)]
            if len(parts) == 2:
                domain, ip_value = parts
                if domain:
                    indicators.append(indicator("domain", domain, attribute))
                normalized_type = ip_indicator_type(ip_value)
                if normalized_type:
                    indicators.append(indicator(normalized_type, ip_value, attribute))
            continue

        if attribute_type in HASH_COMPOSITE_TYPES:
            parts = [part.strip() for part in value.rsplit("|", 1)]
            if len(parts) == 2 and parts[1]:
                indicators.append(
                    indicator(HASH_COMPOSITE_TYPES[attribute_type], parts[1], attribute)
                )
            continue

        normalized_type = MISP_TYPE_MAP.get(attribute_type)
        if normalized_type:
            indicators.append(indicator(normalized_type, value, attribute))

    return indicators


def event_indicators(event):
    indicators = []
    for attribute in event_attributes(event):
        indicators.extend(attribute_to_indicators(attribute))
    return indicators


def event_to_feed_candidate(event, source=MISP_SOURCE, external_id=None):
    event = unwrap_event(event)
    event_id = external_id or event.get("uuid") or event.get("id") or ""
    title = event.get("info") or event_id or "Untitled MISP event"
    created = event_created(event)
    tags = event_tags(event)
    indicators = event_indicators(event)
    provenance = {
        "collector": "misp",
        "original_source": original_source(event),
        "misp_event_id": event.get("id", ""),
        "misp_event_uuid": event.get("uuid", ""),
    }

    raw = dict(event)
    raw.update(
        {
            "id": event_id,
            "name": title,
            "description": event.get("info", ""),
            "created": created,
            "tags": tags,
            "indicators": indicators,
            "provenance": provenance,
        }
    )

    return FeedCandidate(
        source=source,
        external_id=event_id,
        title=title,
        description=event.get("info", ""),
        created=created,
        indicators=indicators,
        tags=tags,
        raw=raw,
    )


class MISPFeedAdapter:
    source = MISP_SOURCE

    def __init__(self, misp_client, source=MISP_SOURCE):
        self.misp_client = misp_client
        self.source = source

    def search(self, query):
        return [
            event_to_feed_candidate(event, self.source)
            for event in self.misp_client.search_events(query)
        ]

    def enrich(self, candidate):
        if not candidate.external_id:
            return None

        event = self.misp_client.get_event(candidate.external_id)
        if not event:
            return None

        return event_to_feed_candidate(event, self.source, candidate.external_id)
