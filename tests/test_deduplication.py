import json
import os
import tempfile
import unittest

from core.deduplication import (
    ARTIFACTS_KEY,
    ARTIFACT_RECORDS_KEY,
    ArtifactDeduplicationIndex,
    indicator_fingerprint,
)


class ArtifactFingerprintTests(unittest.TestCase):
    def test_indicator_fingerprint_normalizes_common_types(self):
        self.assertEqual(
            "domain:example.com",
            indicator_fingerprint({"type": "Domain", "indicator": " Example.COM "}),
        )
        self.assertEqual(
            "filehash-sha256:abc123",
            indicator_fingerprint({"type": "sha256", "indicator": "ABC123"}),
        )
        self.assertEqual(
            "ipv4:8.8.8.8",
            indicator_fingerprint({"type": "ipv4-addr", "indicator": "8.8.8.8"}),
        )

    def test_indicator_fingerprint_skips_missing_values(self):
        self.assertIsNone(indicator_fingerprint({"type": "domain", "indicator": ""}))
        self.assertIsNone(indicator_fingerprint({"type": "", "indicator": "x"}))


class ArtifactDeduplicationIndexTests(unittest.TestCase):
    def test_filter_new_indicators_keeps_unknown_and_counts_known(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "dedup.json")
            with open(state_file, "w") as f:
                json.dump({ARTIFACTS_KEY: ["domain:known.example"]}, f)

            index = ArtifactDeduplicationIndex(state_file)
            filtered, duplicate_count = index.filter_new_indicators(
                [
                    {"type": "domain", "indicator": "known.example"},
                    {"type": "domain", "indicator": "new.example"},
                    {"type": "unsupported", "indicator": "kept"},
                ]
            )

            self.assertEqual(1, duplicate_count)
            self.assertEqual(
                [
                    {"type": "domain", "indicator": "new.example"},
                    {"type": "unsupported", "indicator": "kept"},
                ],
                filtered,
            )

    def test_mark_indicators_is_idempotent_and_persistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "dedup.json")
            index = ArtifactDeduplicationIndex(state_file)

            added = index.mark_indicators(
                [
                    {"type": "domain", "indicator": "Example.com"},
                    {"type": "domain", "indicator": "example.com"},
                    {"type": "sha256", "indicator": "ABC"},
                ]
            )

            self.assertEqual(2, added)
            with open(state_file, "r") as f:
                data = json.load(f)

            self.assertEqual(
                ["domain:example.com", "filehash-sha256:abc"],
                data[ARTIFACTS_KEY],
            )
            self.assertIn(ARTIFACT_RECORDS_KEY, data)
            self.assertTrue(
                ArtifactDeduplicationIndex(state_file).has_fingerprint(
                    "domain:example.com"
                )
            )

    def test_mark_indicators_records_source_correlation_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "dedup.json")
            index = ArtifactDeduplicationIndex(state_file)

            first_added = index.mark_indicators(
                [{"type": "domain", "indicator": "example.com"}],
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="OTX pulse",
            )
            second_added = index.mark_indicators(
                [{"type": "domain", "indicator": "Example.com"}],
                source_key="misp:misp",
                external_id="event-1",
                title="MISP event",
            )

            self.assertEqual(1, first_added)
            self.assertEqual(0, second_added)
            record = ArtifactDeduplicationIndex(state_file).artifact_record(
                "domain:example.com"
            )

            self.assertEqual("domain:example.com", record["fingerprint"])
            self.assertEqual(["alienvault:otx", "misp:misp"], record["sources"])
            self.assertEqual(2, len(record["sightings"]))
            self.assertEqual("pulse-1", record["sightings"][0]["external_id"])
            self.assertEqual("event-1", record["sightings"][1]["external_id"])

    def test_mark_indicators_deduplicates_same_source_sighting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "dedup.json")
            index = ArtifactDeduplicationIndex(state_file)
            indicator = {"type": "domain", "indicator": "example.com"}

            index.mark_indicators(
                [indicator],
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="OTX pulse",
            )
            index.mark_indicators(
                [indicator],
                source_key="alienvault:otx",
                external_id="pulse-1",
                title="OTX pulse",
            )

            record = ArtifactDeduplicationIndex(state_file).artifact_record(
                "domain:example.com"
            )
            self.assertEqual(1, len(record["sightings"]))

    def test_correlation_summary_reads_legacy_and_record_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "dedup.json")
            with open(state_file, "w") as f:
                json.dump({ARTIFACTS_KEY: ["domain:legacy.example"]}, f)

            index = ArtifactDeduplicationIndex(state_file)
            summary = index.correlation_summary(
                [
                    {"type": "domain", "indicator": "legacy.example"},
                    {"type": "domain", "indicator": "new.example"},
                ]
            )

            self.assertEqual(1, summary["known_count"])
            self.assertEqual(["domain:legacy.example"], summary["known_fingerprints"])
            self.assertEqual([], summary["sources"])


if __name__ == "__main__":
    unittest.main()
