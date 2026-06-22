import os
import tempfile
import unittest
from types import SimpleNamespace

from core.quarantine import QuarantineRecord, QuarantineRepository
from gateway.quarantine_export import QuarantineExporter


class QuarantineExportTests(unittest.TestCase):
    def test_dry_run_reports_released_record_without_exporting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository, record = released_repository(tmpdir)
            export_calls = []

            service = QuarantineExporter(
                repository,
                api_client="api",
                exporter=lambda *args, **kwargs: export_calls.append(args) or 1,
                dry_run=True,
            )

            results = service.export_pending(record["quarantine_id"])

            self.assertEqual(1, len(results))
            self.assertEqual("dry-run", results[0].action)
            self.assertEqual(2, results[0].exported_indicator_count)
            self.assertEqual([], export_calls)
            current = repository.get(record["quarantine_id"])
            self.assertFalse(current["review"]["exported"])

    def test_export_released_record_marks_repository_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository, record = released_repository(tmpdir)
            export_calls = []
            marked = []
            artifact_dedup = SimpleNamespace(
                filter_new_indicators=lambda indicators: (indicators[1:], 1),
                mark_indicators=lambda indicators, **kwargs: marked.append(
                    (indicators, kwargs)
                )
                or len(indicators),
            )

            def exporter(api_client, name, description, score, indicators, identity_name):
                export_calls.append(
                    {
                        "api_client": api_client,
                        "name": name,
                        "description": description,
                        "score": score,
                        "indicators": indicators,
                        "identity_name": identity_name,
                    }
                )
                return len(indicators)

            service = QuarantineExporter(
                repository,
                api_client="api",
                exporter=exporter,
                artifact_dedup=artifact_dedup,
                identity_name="NarrowCTI Test",
                dry_run=False,
            )

            results = service.export_pending(record["quarantine_id"])

            self.assertEqual("export", results[0].action)
            self.assertEqual(1, results[0].exported_indicator_count)
            self.assertEqual(1, results[0].dedup_duplicate_count)
            self.assertEqual("Sample pulse", export_calls[0]["name"])
            self.assertEqual("NarrowCTI Test", export_calls[0]["identity_name"])
            self.assertEqual(1, len(export_calls[0]["indicators"]))
            self.assertEqual("url", export_calls[0]["indicators"][0]["type"])
            self.assertEqual(1, len(marked))
            self.assertEqual("alienvault:otx", marked[0][1]["source_key"])
            current = repository.get(record["quarantine_id"])
            self.assertTrue(current["review"]["exported"])
            self.assertEqual(1, current["review"]["exported_indicator_count"])

    def test_partial_release_exports_only_selected_indicator_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
            record = repository.add(sample_record())
            released = repository.release_indicators(
                record["quarantine_id"],
                "domain",
                "Only domain is in scope",
            )
            export_calls = []

            service = QuarantineExporter(
                repository,
                api_client="api",
                exporter=lambda *args, **kwargs: export_calls.append(args) or 1,
                dry_run=False,
            )

            result = service.export_pending(released["quarantine_id"])[0]

            self.assertEqual("export", result.action)
            indicators = export_calls[0][4]
            self.assertEqual([{"type": "domain", "indicator": "example.com"}], indicators)

    def test_all_known_indicators_mark_record_exported_without_opencti_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository, record = released_repository(tmpdir)
            artifact_dedup = SimpleNamespace(
                filter_new_indicators=lambda indicators: ([], len(indicators)),
                mark_indicators=lambda *args, **kwargs: self.fail(
                    "known artifacts should not be marked again"
                ),
            )

            service = QuarantineExporter(
                repository,
                api_client="api",
                exporter=lambda *args, **kwargs: self.fail("export should not run"),
                artifact_dedup=artifact_dedup,
                dry_run=False,
            )

            result = service.export_pending(record["quarantine_id"])[0]

            self.assertEqual("dedup-skip", result.action)
            self.assertEqual(0, result.exported_indicator_count)
            self.assertEqual(2, result.dedup_duplicate_count)
            self.assertTrue(repository.get(record["quarantine_id"])["review"]["exported"])


def released_repository(tmpdir):
    repository = QuarantineRepository(os.path.join(tmpdir, "quarantine.jsonl"))
    record = repository.add(sample_record())
    released = repository.release(record["quarantine_id"], "Relevant")
    return repository, released


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


if __name__ == "__main__":
    unittest.main()
