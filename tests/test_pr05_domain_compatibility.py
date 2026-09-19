import ast
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from core.decision_audit import DecisionRecord
from core.feed_contract import FeedAdapter, FeedCandidate, FeedRunSummary, FeedSource
from core.feed_contract import slugify as legacy_slugify
from core.indicator_policy import (
    filter_indicators_by_type as legacy_filter_indicators_by_type,
    normalize_allowed_indicator_types as legacy_normalize_allowed_indicator_types,
)
from core.policy import PolicyConfig as LegacyPolicyConfig
from core.policy import should_ingest as legacy_should_ingest
from core.scoring import calculate_score as legacy_calculate_score
from core.scoring import calculate_score_details as legacy_calculate_score_details
from core.scoring import age_days as legacy_age_days
from core.tlp import normalize_tlp as legacy_normalize_tlp

from narrowcti.domain.intelligence import feed_contract as domain_feed
from narrowcti.domain.intelligence import indicator_policy as domain_indicator_policy
from narrowcti.domain.intelligence import indicator_types as domain_indicator_types
from narrowcti.domain.intelligence import policy as domain_policy
from narrowcti.domain.intelligence import scoring as domain_scoring
from narrowcti.domain.intelligence import tlp as domain_tlp


ROOT = Path(__file__).resolve().parents[1]
DOMAIN_ROOT = ROOT / "src" / "narrowcti" / "domain" / "intelligence"


class DomainCompatibilityTests(unittest.TestCase):
    def test_domain_and_legacy_imports_preserve_symbol_identity_both_orders(self):
        snippets = (
            """
import narrowcti.domain.intelligence.feed_contract as domain
import core.feed_contract as legacy
assert domain.FeedCandidate is legacy.FeedCandidate
assert domain.FeedSource is legacy.FeedSource
assert domain.slugify is legacy.slugify
""",
            """
import core.feed_contract as legacy
import narrowcti.domain.intelligence.feed_contract as domain
assert domain.FeedCandidate is legacy.FeedCandidate
assert domain.FeedSource is legacy.FeedSource
assert domain.slugify is legacy.slugify
""",
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        for snippet in snippets:
            subprocess.run(
                [sys.executable, "-c", snippet],
                check=True,
                cwd=ROOT,
                env=env,
            )

    def test_migrated_symbols_are_single_canonical_objects(self):
        self.assertIs(FeedSource, domain_feed.FeedSource)
        self.assertIs(FeedCandidate, domain_feed.FeedCandidate)
        self.assertIs(legacy_slugify, domain_feed.slugify)

        self.assertIs(legacy_age_days, domain_scoring.age_days)
        self.assertIs(legacy_calculate_score, domain_scoring.calculate_score)
        self.assertIs(
            legacy_calculate_score_details,
            domain_scoring.calculate_score_details,
        )
        self.assertIs(legacy_normalize_tlp, domain_tlp.normalize_tlp)
        self.assertIs(LegacyPolicyConfig, domain_policy.PolicyConfig)
        self.assertIs(legacy_should_ingest, domain_policy.should_ingest)
        self.assertIs(
            legacy_filter_indicators_by_type,
            domain_indicator_policy.filter_indicators_by_type,
        )
        self.assertIs(
            legacy_normalize_allowed_indicator_types,
            domain_indicator_policy.normalize_allowed_indicator_types,
        )

    def test_deferred_feed_symbols_remain_owned_by_core(self):
        self.assertIsNotNone(FeedAdapter)
        self.assertIsNotNone(FeedRunSummary)
        self.assertFalse(hasattr(domain_feed, "FeedAdapter"))
        self.assertFalse(hasattr(domain_feed, "FeedRunSummary"))

    def test_indicator_types_are_owned_once_and_reexported_by_deduplication(self):
        from core import deduplication

        self.assertIs(deduplication.TYPE_ALIASES, domain_indicator_types.TYPE_ALIASES)
        self.assertIs(
            deduplication.LOWERCASE_VALUE_TYPES,
            domain_indicator_types.LOWERCASE_VALUE_TYPES,
        )
        self.assertIs(
            deduplication.normalize_indicator_type,
            domain_indicator_types.normalize_indicator_type,
        )
        self.assertIs(
            deduplication.normalize_indicator_value,
            domain_indicator_types.normalize_indicator_value,
        )

    def test_decision_record_shape_remains_exactly_legacy(self):
        record = DecisionRecord(
            action="skip",
            reason="already processed",
            source_key="source:test",
            external_id="event-1",
            title="Existing event",
            recorded_at="2026-09-19T00:00:00Z",
        )

        self.assertEqual(
            {
                "action": "skip",
                "reason": "already processed",
                "source_key": "source:test",
                "external_id": "event-1",
                "title": "Existing event",
                "query": "",
                "score": None,
                "age_days": None,
                "indicator_count": 0,
                "recorded_at": "2026-09-19T00:00:00Z",
                "metadata": {},
            },
            record.to_dict(),
        )
        self.assertEqual(
            set(record.to_dict()),
            {
                "action",
                "reason",
                "source_key",
                "external_id",
                "title",
                "query",
                "score",
                "age_days",
                "indicator_count",
                "recorded_at",
                "metadata",
            },
        )
        self.assertEqual(record.to_dict(), json.loads(json.dumps(record.to_dict())))

    def test_domain_modules_have_no_runtime_boundary_imports(self):
        forbidden_prefixes = (
            "core",
            "connectors",
            "gateway",
            "exporters",
            "narrowcti.adapters",
            "narrowcti.infrastructure",
            "narrowcti.api",
            "infrastructure",
            "adapters",
        )

        def is_forbidden(module_name):
            return any(
                module_name == prefix or module_name.startswith(f"{prefix}.")
                for prefix in forbidden_prefixes
            )

        for path in DOMAIN_ROOT.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    imported = [node.module]
                else:
                    continue
                self.assertTrue(
                    not any(is_forbidden(module) for module in imported),
                    f"{path.name} imports forbidden runtime boundary: {imported}",
                )

    def test_domain_imports_do_not_create_core_aliases(self):
        self.assertIsNot(
            sys.modules["narrowcti.domain.intelligence.scoring"],
            sys.modules["core.scoring"],
        )
        self.assertIs(
            domain_scoring.calculate_score,
            sys.modules["core.scoring"].calculate_score,
        )
