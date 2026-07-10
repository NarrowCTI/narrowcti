import json
import os
import tempfile
import unittest

from core.quarantine import QuarantineRecord, QuarantineRepository
from gateway.review import AnalystReviewService, read_audit_events


class AnalystReviewServiceTests(unittest.TestCase):
    def test_lists_records_by_status_and_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            repository = QuarantineRepository(repository_path)
            first = repository.add(sample_record("otx", "pulse-1"))
            second = repository.add(sample_record("misp", "event-1"))
            repository.release(second["quarantine_id"], "Relevant")
            service = AnalystReviewService(repository)

            pending = service.list_records(status="pending")
            misp_records = service.list_records(status="all", source_key="misp")

            self.assertEqual([first["quarantine_id"]], ids(pending))
            self.assertEqual([second["quarantine_id"]], ids(misp_records))

    def test_summary_counts_statuses_sources_and_exportable_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            first = repository.add(sample_record("otx", "pulse-1"))
            second = repository.add(sample_record("misp", "event-1"))
            third = repository.add(sample_record("misp", "event-2"))
            repository.release(first["quarantine_id"], "Relevant")
            repository.release_indicators(second["quarantine_id"], "domain", "Relevant")
            repository.reject(third["quarantine_id"], "Out of scope")
            service = AnalystReviewService(repository)

            summary = service.summary().to_dict()

            self.assertEqual(3, summary["record_count"])
            self.assertEqual(1, summary["status_counts"]["released"])
            self.assertEqual(1, summary["status_counts"]["partially-released"])
            self.assertEqual(1, summary["status_counts"]["rejected"])
            self.assertEqual(1, summary["source_counts"]["otx"])
            self.assertEqual(2, summary["source_counts"]["misp"])
            self.assertEqual(0, summary["pending_count"])
            self.assertEqual(2, summary["exportable_count"])

    def test_release_uses_service_reviewer_and_reason_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record("otx", "pulse-1"))
            service = AnalystReviewService(
                repository,
                reviewer="analyst-a",
                require_reason=False,
            )

            released = service.release(record["quarantine_id"], "")

            self.assertEqual("released", released["status"])
            self.assertEqual("analyst-a", released["review"]["reviewer"])
            self.assertEqual("", released["review"]["reason"])

    def test_audit_events_can_filter_by_id_action_and_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            audit_path = os.path.join(tmpdir, "releases.jsonl")
            repository = QuarantineRepository(repository_path, audit_path)
            first = repository.add(sample_record("otx", "pulse-1"))
            second = repository.add(sample_record("misp", "event-1"))
            service = AnalystReviewService(repository)
            service.release(first["quarantine_id"], "Relevant")
            service.reject(second["quarantine_id"], "Out of scope")

            events = service.audit_events(action="reject", limit=1)

            self.assertEqual(1, len(events))
            self.assertEqual("reject", events[0]["action"])
            self.assertEqual(second["quarantine_id"], events[0]["quarantine_id"])
            self.assertEqual(events, read_audit_events(audit_path)[-1:])

    def test_read_audit_events_accepts_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = os.path.join(tmpdir, "releases.jsonl")
            with open(audit_path, "w", encoding="utf-8-sig") as file_obj:
                file_obj.write(json.dumps({"action": "release"}) + "\n")

            events = read_audit_events(audit_path)

        self.assertEqual("release", events[0]["action"])

    def test_export_released_runs_dry_run_without_marking_exported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record("otx", "pulse-1"))
            released = repository.release(record["quarantine_id"], "Relevant")
            service = AnalystReviewService(repository)

            result = service.export_released(released["quarantine_id"])[0].to_dict()

            self.assertEqual("dry-run", result["action"])
            self.assertTrue(result["dry_run"])
            self.assertEqual(2, result["exported_indicator_count"])
            self.assertFalse(
                repository.get(released["quarantine_id"])["review"]["exported"]
            )


def sample_record(source_key, external_id):
    return QuarantineRecord(
        source_key=source_key,
        external_id=external_id,
        title=f"Record {external_id}",
        reason="low score",
        indicators=[
            {"type": "domain", "indicator": f"{external_id}.example"},
            {"type": "url", "indicator": f"https://{external_id}.example/a"},
        ],
    )


def ids(records):
    return [record["quarantine_id"] for record in records]


if __name__ == "__main__":
    unittest.main()
