import json
import os
import tempfile
import unittest

from core.quarantine import (
    PARTIALLY_RELEASED,
    REJECTED,
    RELEASED,
    QuarantineRecord,
    QuarantineRepository,
    released_indicators,
)


class QuarantineRepositoryTests(unittest.TestCase):
    def test_add_persists_pending_record_with_stable_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))

            record = repository.add(sample_record())

            self.assertTrue(record["quarantine_id"].startswith("q-"))
            self.assertEqual("pending", record["status"])
            self.assertEqual(2, record["indicator_count"])
            self.assertEqual(record["quarantine_id"], repository.records()[0]["quarantine_id"])
            self.assertEqual(1, len(repository.events()))

    def test_add_is_idempotent_for_same_quarantine_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))

            first = repository.add(sample_record())
            second = repository.add(sample_record())

            self.assertEqual(first["quarantine_id"], second["quarantine_id"])
            self.assertEqual(1, len(repository.events()))
            self.assertEqual(1, len(repository.records()))

    def test_reject_appends_transition_and_release_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(
                os.path.join(tmpdir, "quarantine.jsonl"),
                os.path.join(tmpdir, "releases.jsonl"),
            )
            record = repository.add(sample_record())

            rejected = repository.reject(
                record["quarantine_id"],
                "Out of scope",
                reviewer="analyst",
            )

            self.assertEqual(REJECTED, rejected["status"])
            self.assertEqual("reject", rejected["review"]["action"])
            self.assertEqual("analyst", rejected["review"]["reviewer"])
            self.assertEqual(2, len(repository.events()))
            audit = read_jsonl(os.path.join(tmpdir, "releases.jsonl"))
            self.assertEqual(1, len(audit))
            self.assertEqual(REJECTED, audit[0]["status"])
            self.assertEqual("Out of scope", audit[0]["reason"])

    def test_release_requires_reason_when_configured(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record())

            with self.assertRaises(ValueError):
                repository.release(record["quarantine_id"], "")

    def test_release_marks_all_indicators_without_exporting_yet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record())

            released = repository.release(
                record["quarantine_id"],
                "Relevant to monitored actor",
                reviewer="cti",
            )

            self.assertEqual(RELEASED, released["status"])
            self.assertEqual(2, released["review"]["released_indicator_count"])
            self.assertEqual(0, released["review"]["held_indicator_count"])
            self.assertFalse(released["review"]["exported"])
            self.assertEqual(2, len(released_indicators(released)))

    def test_partial_release_filters_indicator_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record())

            released = repository.release_indicators(
                record["quarantine_id"],
                "domain",
                "Domain is relevant",
            )

            self.assertEqual(PARTIALLY_RELEASED, released["status"])
            self.assertEqual(["domain"], released["review"]["released_indicator_types"])
            self.assertEqual(1, released["review"]["released_indicator_count"])
            self.assertEqual(1, released["review"]["held_indicator_count"])
            self.assertEqual(
                [{"type": "domain", "indicator": "example.com"}],
                released_indicators(released),
            )

    def test_mark_exported_appends_export_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(
                os.path.join(tmpdir, "quarantine.jsonl"),
                os.path.join(tmpdir, "releases.jsonl"),
            )
            record = repository.add(sample_record())
            released = repository.release(record["quarantine_id"], "Relevant")

            exported = repository.mark_exported(
                released["quarantine_id"],
                exported_indicator_count=2,
                dedup_duplicate_count=1,
                exported_by="unit-test",
            )

            self.assertTrue(exported["review"]["exported"])
            self.assertEqual("unit-test", exported["review"]["exported_by"])
            self.assertEqual(2, exported["review"]["exported_indicator_count"])
            self.assertEqual(1, exported["review"]["dedup_duplicate_count"])
            self.assertEqual(3, len(repository.events()))
            audit = read_jsonl(os.path.join(tmpdir, "releases.jsonl"))
            self.assertTrue(audit[-1]["exported"])
            self.assertEqual(2, audit[-1]["exported_indicator_count"])

    def test_cannot_transition_non_pending_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record())
            repository.reject(record["quarantine_id"], "Out of scope")

            with self.assertRaises(ValueError):
                repository.release(record["quarantine_id"], "Changed my mind")


def sample_record():
    return QuarantineRecord(
        source_key="alienvault:otx",
        external_id="pulse-1",
        title="Sample pulse",
        query="lummac2",
        reason="low score",
        score=40,
        age_days=10,
        indicators=[
            {"type": "domain", "indicator": "example.com"},
            {"type": "filehash-sha256", "indicator": "a" * 64},
        ],
        metadata={"tags": ["tlp:green"]},
        raw_snapshot={"id": "pulse-1"},
    )


def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as file_obj:
        return [json.loads(line) for line in file_obj if line.strip()]


if __name__ == "__main__":
    unittest.main()
