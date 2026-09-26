import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


LEGACY_SYMBOLS = r'''
from core.feed_contract import FeedCandidate as legacy_candidate
from core.feed_contract import FeedSource as legacy_source
from core.feed_contract import slugify as legacy_slugify
from core.scoring import calculate_score as legacy_score
from core.contextual_scoring import build_contextual_score_evidence as legacy_contextual
from core.tlp import normalize_tlp as legacy_tlp
from core.policy import should_ingest as legacy_policy
from core.deduplication import normalize_indicator_type as legacy_indicator_type
from core.indicator_policy import filter_indicators_by_type as legacy_indicator_policy
from core.quarantine import QuarantineRecord as legacy_record
from core.quarantine import QuarantineRepository as legacy_repository
from connectors.misp.feed_adapter import MISPFeedAdapter as legacy_misp_adapter
from exporters.stix_builder import build_report_bundle as legacy_bundle
from gateway.feature_gates import FeatureGateState as legacy_gate
from gateway.feature_gates import build_feature_gate_state as legacy_gate_builder
from narrowcti.domain.intelligence.feed_contract import FeedCandidate as canonical_candidate
from narrowcti.domain.intelligence.feed_contract import FeedSource as canonical_source
from narrowcti.domain.intelligence.feed_contract import slugify as canonical_slugify
from narrowcti.domain.intelligence.scoring import calculate_score as canonical_score
from narrowcti.domain.intelligence.contextual_scoring import build_contextual_score_evidence as canonical_contextual
from narrowcti.domain.intelligence.tlp import normalize_tlp as canonical_tlp
from narrowcti.domain.intelligence.policy import should_ingest as canonical_policy
from narrowcti.domain.intelligence.indicator_types import normalize_indicator_type as canonical_indicator_type
from narrowcti.domain.intelligence.indicator_policy import filter_indicators_by_type as canonical_indicator_policy
from narrowcti.domain.review.quarantine import QuarantineRecord as canonical_record
from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository as canonical_repository
from connectors.misp.feed_adapter import MISPFeedAdapter as canonical_misp_adapter
from narrowcti.adapters.stix.serializer import build_report_bundle as canonical_bundle
from gateway.feature_gates import FeatureGateState as canonical_gate
from gateway.feature_gates import build_feature_gate_state as canonical_gate_builder
assert legacy_candidate is canonical_candidate
assert legacy_source is canonical_source
assert legacy_slugify is canonical_slugify
assert legacy_score is canonical_score
assert legacy_contextual is canonical_contextual
assert legacy_tlp is canonical_tlp
assert legacy_policy is canonical_policy
assert legacy_indicator_type is canonical_indicator_type
assert legacy_indicator_policy is canonical_indicator_policy
assert legacy_record is canonical_record
assert legacy_repository is canonical_repository
assert legacy_misp_adapter is canonical_misp_adapter
assert legacy_bundle is canonical_bundle
assert legacy_gate is canonical_gate
assert legacy_gate_builder is canonical_gate_builder
'''


class PackageCompatibilityTests(unittest.TestCase):
    def _run_source_import(self, code):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_legacy_symbols_resolve_to_canonical_owners(self):
        self._run_source_import(LEGACY_SYMBOLS)

    def test_removed_nested_facades_are_not_importable(self):
        for module_name in (
            "narrowcti.core.feed_contract",
            "narrowcti.connectors.misp.feed_adapter",
            "narrowcti.exporters.stix_builder",
            "narrowcti.gateway.settings",
        ):
            result = subprocess.run(
                [sys.executable, "-c", f"import {module_name}"],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT)))},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, module_name)
            self.assertIn("No module named", result.stderr)

    def test_source_mode_package_import_is_independent_of_distribution_metadata(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        code = """
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

with patch("importlib.metadata.version", side_effect=PackageNotFoundError("narrowcti")):
    import narrowcti
    print(narrowcti.__version__)
"""
        result = subprocess.run(
            [sys.executable, "-S", "-c", code],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "0+unknown")

    def test_otx_connector_preserves_historical_script_contract(self):
        connector = (ROOT / "connectors" / "otx" / "connector.py").read_text(encoding="utf-8")
        dockerfile = (ROOT / "connectors" / "otx" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("from otx_client import OTXClient", connector)
        self.assertIn("from processor import OTXProcessor", connector)
        self.assertIn('CMD ["python", "connector.py"]', dockerfile)
        self.assertNotIn("sys.path", connector)

    def test_otx_package_imports_are_not_current_contract(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
        result = subprocess.run(
            [sys.executable, "-c", "import connectors.otx.connector"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No module named 'otx_client'", result.stderr)


if __name__ == "__main__":
    unittest.main()
