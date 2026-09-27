from narrowcti.adapters.stix.patterns import indicator_pattern


INDICATOR_LOOKUP_QUERY = """
query NarrowCTIIndicatorDedupLookup($filters: FilterGroup) {
  indicators(first: 1, filters: $filters) {
    edges {
      node {
        id
      }
    }
  }
}
"""


class OpenCTIArtifactLookup:
    def __init__(self, api_client, logger=None):
        self.api_client = api_client
        self.logger = logger or (lambda message: None)

    def has_indicator(self, indicator):
        pattern = indicator_pattern(indicator)
        if not pattern:
            return False

        variables = {
            "filters": {
                "mode": "and",
                "filters": [
                    {
                        "key": "pattern",
                        "values": [pattern],
                        "operator": "eq",
                    }
                ],
                "filterGroups": [],
            }
        }
        try:
            result = self.api_client.query(INDICATOR_LOOKUP_QUERY, variables)
        except Exception as exc:
            self.logger(f"OpenCTI dedup lookup failed: pattern={pattern} error={exc}")
            return False

        edges = (((result or {}).get("data") or {}).get("indicators") or {}).get(
            "edges",
            [],
        )
        return bool(edges)

    def has_indicator_for_recovery(self, indicator):
        """Strict lookup for a reclaimed export attempt; errors fail closed."""
        pattern = indicator_pattern(indicator)
        if not pattern:
            raise RuntimeError("OpenCTI recovery lookup cannot identify indicator")
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "pattern", "values": [pattern], "operator": "eq"}],
                "filterGroups": [],
            }
        }
        try:
            result = self.api_client.query(INDICATOR_LOOKUP_QUERY, variables)
        except Exception as exc:
            raise RuntimeError("OpenCTI recovery lookup failed") from exc
        if not isinstance(result, dict) or result.get("errors"):
            raise RuntimeError("OpenCTI recovery lookup returned an invalid response")
        data = result.get("data")
        indicators = data.get("indicators") if isinstance(data, dict) else None
        edges = indicators.get("edges") if isinstance(indicators, dict) else None
        if not isinstance(edges, list):
            raise RuntimeError("OpenCTI recovery lookup returned an invalid response")
        for edge in edges:
            node = edge.get("node") if isinstance(edge, dict) else None
            if not isinstance(node, dict) or not node.get("id"):
                raise RuntimeError("OpenCTI recovery lookup returned an invalid response")
        return bool(edges)


class CompositeArtifactDeduplication:
    def __init__(self, local_index=None, opencti_lookup=None, logger=None):
        self.local_index = local_index
        self.opencti_lookup = opencti_lookup
        self.logger = logger or (lambda message: None)

    def filter_new_indicators(self, indicators):
        candidates = list(indicators or [])
        duplicate_count = 0

        if self.local_index:
            candidates, duplicate_count = self.local_index.filter_new_indicators(
                candidates
            )

        if not self.opencti_lookup:
            return candidates, duplicate_count

        filtered = []
        opencti_duplicates = 0
        for indicator in candidates:
            if self.opencti_lookup.has_indicator(indicator):
                opencti_duplicates += 1
                continue
            filtered.append(indicator)

        if opencti_duplicates:
            self.logger(
                f"OpenCTI artifact dedup: duplicates={opencti_duplicates}"
            )
        return filtered, duplicate_count + opencti_duplicates

    def mark_indicators(
        self,
        indicators,
        source_key="",
        external_id="",
        title="",
    ):
        if not self.local_index:
            return 0
        return self.local_index.mark_indicators(
            indicators,
            source_key=source_key,
            external_id=external_id,
            title=title,
        )


__all__ = [
    "INDICATOR_LOOKUP_QUERY",
    "OpenCTIArtifactLookup",
    "CompositeArtifactDeduplication",
    "indicator_pattern",
]
