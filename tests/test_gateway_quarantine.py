import contextlib
import io
import json
import os
import tempfile
import unittest

from core.quarantine import QuarantineRecord, QuarantineRepository
from gateway.quarantine import main


class GatewayQuarantineCliTests(unittest.TestCase):
    def test_list_and_show_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            record = seed_record(repository_path)

            list_output = run_cli(
                "--repository",
                repository_path,
                "list",
            )
            show_output = run_cli(
                "--repository",
                repository_path,
                "show",
                "--id",
                record["quarantine_id"],
            )

            self.assertIn("NarrowCTI quarantine list", list_output)
            self.assertIn("count=1", list_output)
            self.assertIn(record["quarantine_id"], list_output)
            self.assertIn("NarrowCTI quarantine record", show_output)
            self.assertIn("source_key=alienvault:otx", show_output)
            self.assertIn("domain=example.com", show_output)

    def test_reject_updates_record_and_writes_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            audit_path = os.path.join(tmpdir, "releases.jsonl")
            record = seed_record(repository_path)

            output = run_cli(
                "--repository",
                repository_path,
                "--release-audit-file",
                audit_path,
                "reject",
                "--id",
                record["quarantine_id"],
                "--reason",
                "Not relevant",
                "--reviewer",
                "analyst",
            )

            self.assertIn("status=rejected", output)
            self.assertIn("- reviewer=analyst", output)
            audit = read_jsonl(audit_path)
            self.assertEqual("reject", audit[0]["action"])
            self.assertEqual("Not relevant", audit[0]["reason"])

    def test_release_indicators_json_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            record = seed_record(repository_path)

            output = run_cli(
                "--repository",
                repository_path,
                "--json",
                "release-indicators",
                "--id",
                record["quarantine_id"],
                "--type",
                "domain",
                "--reason",
                "Domain is in scope",
            )

            data = json.loads(output)
            self.assertEqual("partially-released", data["status"])
            self.assertEqual(["domain"], data["review"]["released_indicator_types"])
            self.assertEqual(1, data["review"]["released_indicator_count"])
            self.assertEqual(1, data["review"]["held_indicator_count"])

    def test_export_released_defaults_to_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            repository = QuarantineRepository(repository_path)
            record = repository.add(sample_record())
            released = repository.release(record["quarantine_id"], "Relevant")

            output = run_cli(
                "--repository",
                repository_path,
                "export-released",
                "--id",
                released["quarantine_id"],
            )

            self.assertIn("NarrowCTI quarantine export", output)
            self.assertIn("action=dry-run", output)
            self.assertIn("exported_indicators=2", output)
            self.assertFalse(
                repository.get(released["quarantine_id"])["review"]["exported"]
            )

    def test_audit_lists_release_events(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            audit_path = os.path.join(tmpdir, "releases.jsonl")
            record = seed_record(repository_path)

            run_cli(
                "--repository",
                repository_path,
                "--release-audit-file",
                audit_path,
                "release",
                "--id",
                record["quarantine_id"],
                "--reason",
                "Relevant",
                "--reviewer",
                "analyst",
            )
            output = run_cli(
                "--release-audit-file",
                audit_path,
                "audit",
                "--id",
                record["quarantine_id"],
            )

            self.assertIn("NarrowCTI quarantine release audit", output)
            self.assertIn("count=1", output)
            self.assertIn(f"id={record['quarantine_id']}", output)
            self.assertIn("action=release", output)
            self.assertIn("reviewer=analyst", output)
            self.assertIn("reason=Relevant", output)

    def test_audit_json_can_filter_by_action_and_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository_path = os.path.join(tmpdir, "quarantine.jsonl")
            audit_path = os.path.join(tmpdir, "releases.jsonl")
            first = seed_record(repository_path)
            second = QuarantineRepository(repository_path).add(
                QuarantineRecord(
                    source_key="misp:misp",
                    external_id="event-1",
                    title="Sample event",
                    reason="low score",
                    indicators=[{"type": "domain", "indicator": "misp.example"}],
                )
            )

            run_cli(
                "--repository",
                repository_path,
                "--release-audit-file",
                audit_path,
                "release",
                "--id",
                first["quarantine_id"],
                "--reason",
                "Relevant",
            )
            run_cli(
                "--repository",
                repository_path,
                "--release-audit-file",
                audit_path,
                "reject",
                "--id",
                second["quarantine_id"],
                "--reason",
                "Out of scope",
            )
            output = run_cli(
                "--release-audit-file",
                audit_path,
                "--json",
                "audit",
                "--action",
                "reject",
                "--limit",
                "1",
            )

            events = json.loads(output)
            self.assertEqual(1, len(events))
            self.assertEqual("reject", events[0]["action"])
            self.assertEqual(second["quarantine_id"], events[0]["quarantine_id"])


def run_cli(*args):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exit_code = main(list(args))
    if exit_code:
        raise AssertionError(f"CLI returned {exit_code}")
    return output.getvalue()


def seed_record(repository_path):
    repository = QuarantineRepository(repository_path)
    return repository.add(sample_record())


def sample_record():
    return QuarantineRecord(
        source_key="alienvault:otx",
        external_id="pulse-1",
        title="Sample pulse",
        query="lummac2",
        reason="low score",
        score=40,
        indicators=[
            {"type": "domain", "indicator": "example.com"},
            {"type": "url", "indicator": "https://example.com/a"},
        ],
        metadata={"tags": ["tlp:green"]},
    )


def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as file_obj:
        return [json.loads(line) for line in file_obj if line.strip()]


if __name__ == "__main__":
    unittest.main()
