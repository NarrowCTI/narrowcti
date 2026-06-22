import unittest
from types import SimpleNamespace

from core.opencti_deduplication import (
    CompositeArtifactDeduplication,
    OpenCTIArtifactLookup,
)


class OpenCTIArtifactLookupTests(unittest.TestCase):
    def test_has_indicator_queries_opencti_by_stix_pattern(self):
        calls = []

        def query(query_text, variables):
            calls.append((query_text, variables))
            return {"data": {"indicators": {"edges": [{"node": {"id": "indicator--1"}}]}}}

        lookup = OpenCTIArtifactLookup(SimpleNamespace(query=query))

        self.assertTrue(
            lookup.has_indicator({"type": "domain", "indicator": "example.com"})
        )
        self.assertIn("indicators", calls[0][0])
        self.assertEqual(
            "[domain-name:value = 'example.com']",
            calls[0][1]["filters"]["filters"][0]["values"][0],
        )

    def test_has_indicator_fails_open_when_opencti_lookup_errors(self):
        logs = []

        def query(*args, **kwargs):
            raise RuntimeError("OpenCTI unavailable")

        lookup = OpenCTIArtifactLookup(SimpleNamespace(query=query), logger=logs.append)

        self.assertFalse(
            lookup.has_indicator({"type": "domain", "indicator": "example.com"})
        )
        self.assertIn("OpenCTI dedup lookup failed", logs[0])


class CompositeArtifactDeduplicationTests(unittest.TestCase):
    def test_filter_new_indicators_combines_local_and_opencti_duplicates(self):
        local = SimpleNamespace(
            filter_new_indicators=lambda indicators: (indicators[1:], 1),
            mark_indicators=lambda indicators: len(indicators),
        )
        lookup = SimpleNamespace(
            has_indicator=lambda indicator: indicator["indicator"] == "opencti.example"
        )
        logs = []
        dedup = CompositeArtifactDeduplication(
            local_index=local,
            opencti_lookup=lookup,
            logger=logs.append,
        )

        filtered, duplicate_count = dedup.filter_new_indicators(
            [
                {"type": "domain", "indicator": "local.example"},
                {"type": "domain", "indicator": "opencti.example"},
                {"type": "domain", "indicator": "new.example"},
            ]
        )

        self.assertEqual(2, duplicate_count)
        self.assertEqual([{"type": "domain", "indicator": "new.example"}], filtered)
        self.assertEqual(1, dedup.mark_indicators(filtered))
        self.assertIn("OpenCTI artifact dedup: duplicates=1", logs)

    def test_filter_new_indicators_can_run_with_opencti_only(self):
        lookup = SimpleNamespace(has_indicator=lambda indicator: True)
        dedup = CompositeArtifactDeduplication(opencti_lookup=lookup)

        filtered, duplicate_count = dedup.filter_new_indicators(
            [{"type": "domain", "indicator": "known.example"}]
        )

        self.assertEqual([], filtered)
        self.assertEqual(1, duplicate_count)
        self.assertEqual(0, dedup.mark_indicators(filtered))


if __name__ == "__main__":
    unittest.main()
