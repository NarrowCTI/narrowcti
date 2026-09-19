import os
import subprocess
import sys
import unittest
from pathlib import Path

from core.quarantine import QuarantineRecord, QuarantineRepository
from narrowcti.domain.review.quarantine import (
    transition_mark_exported,
    transition_release,
    transition_release_indicators,
    utc_now,
)
from narrowcti.ports.quarantine import QuarantineStore


ROOT = Path(__file__).resolve().parents[1]


class QuarantineDomainTests(unittest.TestCase):
    def test_canonical_domain_owns_utc_format_and_not_core_clock(self):
        source = (
            ROOT / "src" / "narrowcti" / "domain" / "review" / "quarantine.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("core.decision_audit", source)
        self.assertRegex(utc_now(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

        record = QuarantineRecord(
            source_key="source:test",
            external_id="item-1",
            title="Example",
            reason="low score",
            created_at="2026-09-19T10:00:00Z",
        ).to_dict()
        recorded_at = "2026-09-19T10:01:02Z"
        updated = transition_release(
            record,
            "reviewed",
            reviewer="analyst",
            recorded_at=recorded_at,
        )
        self.assertEqual(recorded_at, updated["updated_at"])
        self.assertEqual(recorded_at, updated["review"]["recorded_at"])

    def test_partial_release_preserves_quarantine_type_semantics(self):
        record = QuarantineRecord(
            source_key="source:test",
            external_id="item-2",
            title="Example",
            reason="low score",
            indicators=[
                {"type": "domain-name", "indicator": "alias.example"},
                {"indicator_type": "domain", "indicator": "example.com"},
                {"observable_type": "url", "indicator": "https://example.com"},
            ],
        ).to_dict()

        updated = transition_release_indicators(
            record,
            " Domain ",
            "only domain",
            recorded_at="2026-09-19T10:02:03Z",
        )

        self.assertEqual("partially-released", updated["status"])
        self.assertEqual(["domain"], updated["review"]["released_indicator_types"])
        self.assertEqual(1, updated["review"]["released_indicator_count"])

    def test_export_transition_requires_explicit_timestamp(self):
        record = QuarantineRecord(
            source_key="source:test",
            external_id="item-3",
            title="Example",
            reason="low score",
            indicators=[{"type": "domain", "indicator": "example.com"}],
        ).to_dict()
        released = transition_release(
            record,
            "reviewed",
            recorded_at="2026-09-19T10:03:04Z",
        )
        exported = transition_mark_exported(
            released,
            0,
            dedup_duplicate_count=1,
            recorded_at="2026-09-19T10:04:05Z",
        )
        self.assertEqual("2026-09-19T10:04:05Z", exported["review"]["exported_at"])
        self.assertEqual(1, exported["review"]["dedup_duplicate_count"])

    def test_concrete_repository_satisfies_minimal_store(self):
        repository = QuarantineRepository("unused")
        self.assertIsInstance(repository, QuarantineStore)

    def test_legacy_and_canonical_quarantine_symbols_are_identical_both_orders(self):
        snippets = (
            """
import sys
import core.quarantine as legacy
import narrowcti.core.quarantine as facade
import narrowcti.domain.review.quarantine as domain
import narrowcti.adapters.persistence.local.quarantine_repository as adapter
assert sys.modules['core.quarantine'] is sys.modules['narrowcti.core.quarantine']
assert legacy is facade
assert legacy.QuarantineRecord is domain.QuarantineRecord
assert legacy.QuarantineRepository is adapter.QuarantineRepository
""",
            """
import sys
import narrowcti.core.quarantine as facade
import narrowcti.domain.review.quarantine as domain
import narrowcti.adapters.persistence.local.quarantine_repository as adapter
import core.quarantine as legacy
assert sys.modules['core.quarantine'] is sys.modules['narrowcti.core.quarantine']
assert legacy is facade
assert legacy.QuarantineRecord is domain.QuarantineRecord
assert legacy.QuarantineRepository is adapter.QuarantineRepository
""",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        for snippet in snippets:
            subprocess.run(
                [sys.executable, "-c", snippet],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
