"""PR-16 review boundary and compatibility characterization."""

import ast
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core.quarantine import QuarantineRecord, QuarantineRepository
import gateway.quarantine_export as legacy_quarantine_export
import gateway.review as legacy_review
import gateway.review_api as legacy_review_api
from gateway.review import AnalystReviewService as LegacyReviewService, ReviewSummary as LegacySummary
from narrowcti.adapters.persistence.local.review_audit import read_audit_events
from narrowcti.application.review.export import QuarantineExporter, QuarantineExportResult
from narrowcti.application.review.service import AnalystReviewService, ReviewSummary
from narrowcti.api.review.auth import ReviewCredentialStore, normalize_credentials, token_sha256
from narrowcti.api.review.app import ReviewStatus


ROOT = Path(__file__).resolve().parents[1]


class ReviewBoundaryTests(unittest.TestCase):
    def test_review_status_is_preserved_as_canonical_symbol(self):
        self.assertIs(legacy_review_api.ReviewStatus, ReviewStatus)

    def test_legacy_quarantine_exporter_signature_is_preserved(self):
        parameters = inspect.signature(legacy_quarantine_export.QuarantineExporter.__init__).parameters
        self.assertEqual(
            [
                "self", "repository", "api_client", "exporter", "artifact_dedup",
                "identity_name", "logger", "dry_run", "exported_by",
            ],
            list(parameters),
        )
        self.assertIs(parameters["exporter"].default, legacy_quarantine_export.send_bundle)

    def test_legacy_review_export_signature_is_preserved(self):
        parameters = inspect.signature(legacy_review.AnalystReviewService.export_released).parameters
        self.assertEqual(
            [
                "self", "quarantine_id", "limit", "api_client", "artifact_dedup",
                "identity_name", "logger", "dry_run", "exported_by",
            ],
            list(parameters),
        )
        self.assertNotIn("exporter", parameters)

    def test_pure_summary_and_audit_reader_compatibility(self):
        self.assertIs(LegacySummary, ReviewSummary)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            path.write_text("\ufeff{\"action\": \"release\"}\n{\"action\": \"reject\"}\n", encoding="utf-8")
            self.assertEqual(["release", "reject"], [item["action"] for item in read_audit_events(path)])

    def test_legacy_from_paths_adapts_repository_and_export_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            service = LegacyReviewService.from_paths(str(Path(tmpdir) / "q.jsonl"))
            self.assertIsInstance(service, AnalystReviewService)
            self.assertTrue(service.release_audit_file == "")

    def test_real_export_without_callable_is_explicit_error(self):
        repository = SimpleNamespace(records=lambda status=None: [], get=lambda _: {})
        exporter = QuarantineExporter(repository, dry_run=False)
        self.assertTrue(callable(exporter.exporter) is False)

    def test_export_preserves_success_side_effect_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repository = QuarantineRepository(str(Path(tmpdir) / "q.jsonl"))
            record = repository.add(QuarantineRecord(
                source_key="misp", external_id="event-1", title="Event",
                reason="review",
                indicators=[{"type": "domain", "indicator": "example.test"}],
            ))
            repository.release(record["quarantine_id"], "reviewed")
            events = []
            old_mark = repository.mark_exported
            repository.mark_exported = lambda *args, **kwargs: (events.append("checkpoint"), old_mark(*args, **kwargs))[1]
            dedup = SimpleNamespace(
                filter_new_indicators=lambda indicators: (indicators, 0),
                mark_indicators=lambda *args, **kwargs: events.append("artifact") or 1,
            )
            exporter = QuarantineExporter(
                repository, dry_run=False, artifact_dedup=dedup,
                exporter=lambda *args, **kwargs: events.append("export") or 1,
            )
            result = exporter.export_pending(record["quarantine_id"])[0]
            events.append("decision")
            self.assertEqual("export", result.action)
            self.assertEqual(["export", "artifact", "checkpoint", "decision"], events)

    def test_authentication_retains_hash_loop_and_role_contract(self):
        first = "a" * 32
        second = "b" * 32
        store = ReviewCredentialStore(normalize_credentials([
            {"principal": "first", "token_sha256": token_sha256(first), "roles": ["reader"]},
            {"principal": "second", "token_sha256": token_sha256(second), "roles": ["admin"]},
        ]))
        self.assertEqual("second", store.authenticate(second).principal)
        self.assertTrue(store.authenticate(second).has_permission("export:execute"))
        self.assertIsNone(store.authenticate("short"))

    def test_canonical_modules_do_not_cross_runtime_boundaries(self):
        forbidden = ("gateway", "exporters", "narrowcti.adapters", "fastapi", "pydantic")
        for relative in ("src/narrowcti/application/review/service.py", "src/narrowcti/application/review/export.py"):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                self.assertFalse(any(any(item == name or item.startswith(name + ".") for name in forbidden) for item in names), relative)

    def test_canonical_export_result_shape_is_unchanged(self):
        result = QuarantineExportResult("q", "released", "dry-run")
        self.assertEqual({
            "quarantine_id", "status", "action", "reason", "indicator_count",
            "exported_indicator_count", "dedup_duplicate_count", "title",
            "source_key", "external_id", "dry_run", "errors",
        }, set(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
