"""Bounded local evidence acquisition and safe application projection."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from narrowcti.adapters.persistence.local.web_evidence_reader import read_recent_records
from narrowcti.application.reporting.web_evidence import WebEvidenceService


class WebEvidenceTests(unittest.TestCase):
    def test_service_projects_only_allowlisted_bounded_fields(self):
        service = WebEvidenceService(lambda _limit: [{
            "action": "ingest",
            "reason": "synthetic",
            "external_id": "x" * 400,
            "metadata": {"secret": "do-not-render"},
            "path": "C:/private/secret.jsonl",
        }])
        record = service.recent(1)[0]
        self.assertEqual(256, len(record["external_id"]))
        self.assertNotIn("metadata", record)
        self.assertNotIn("path", record)
        self.assertNotIn("do-not-render", repr(record))

    def test_local_reader_reads_only_jsonl_from_configured_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "decision.jsonl").write_text(
                json.dumps({"action": "drop", "metadata": {"raw": "private"}}) + "\n",
                encoding="utf-8",
            )
            (root / "ignored.json").write_text(json.dumps({"action": "ingest"}), encoding="utf-8")
            records = read_recent_records(directory, limit=10)
        self.assertEqual(1, len(records))
        self.assertEqual("drop", records[0]["action"])

    def test_missing_directory_is_an_empty_safe_result(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual([], read_recent_records(str(Path(directory) / "missing"), 10))


if __name__ == "__main__":
    unittest.main()
