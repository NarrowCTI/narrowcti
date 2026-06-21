from core.feed_contract import FeedCandidate, FeedSource


OTX_SOURCE = FeedSource(
    name="OTX",
    source_type="external_import",
    provider="AlienVault",
    default_confidence=50,
)


def pulse_tags(pulse):
    tags = pulse.get("tags") or pulse.get("industries") or []
    if isinstance(tags, str):
        return [tags]
    return list(tags)


def pulse_to_feed_candidate(pulse, source=OTX_SOURCE, external_id=None):
    pulse_id = external_id or pulse.get("id") or ""
    name = pulse.get("name") or pulse_id or "Untitled OTX pulse"
    raw = dict(pulse)

    if pulse_id and not raw.get("id"):
        raw["id"] = pulse_id

    if name and not raw.get("name"):
        raw["name"] = name

    return FeedCandidate(
        source=source,
        external_id=pulse_id,
        title=name,
        description=pulse.get("description", ""),
        created=pulse.get("created"),
        indicators=pulse.get("indicators", []),
        tags=pulse_tags(pulse),
        raw=raw,
    )


class OTXFeedAdapter:
    source = OTX_SOURCE

    def __init__(self, otx_client, source=OTX_SOURCE):
        self.otx_client = otx_client
        self.source = source

    def search(self, query):
        return [
            pulse_to_feed_candidate(pulse, self.source)
            for pulse in self.otx_client.search_pulses(query)
        ]

    def enrich(self, candidate):
        if not candidate.external_id:
            return None

        pulse = self.otx_client.enrich_pulse(candidate.external_id)
        if not pulse:
            return None

        return pulse_to_feed_candidate(pulse, self.source, candidate.external_id)
