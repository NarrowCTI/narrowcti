"""PR-13 graph provider, domain-boundary, and compatibility characterization."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys
import unittest

from narrowcti.domain.graph import deduplication as domain_deduplication
from narrowcti.ports.graph import GraphIndex, GraphProvider
from narrowcti.ports.graph_index import GraphIndex as CanonicalGraphIndex


ROOT = Path(__file__).resolve().parents[1]


class PR13GraphProviderBoundaryTests(unittest.TestCase):
    def test_graph_index_has_one_canonical_protocol_owner(self):
        from narrowcti.ports import graph as compatibility_graph

        self.assertIs(GraphIndex, CanonicalGraphIndex)
        self.assertIs(compatibility_graph.GraphIndex, CanonicalGraphIndex)

    def test_provider_contract_contains_only_current_plan_lookup(self):
        methods = {
            name
            for name, value in GraphProvider.__dict__.items()
            if callable(value) and not name.startswith("_")
        }
        self.assertEqual(methods, {"known_keys_for_plan"})

    def test_opencti_adapters_satisfy_the_consumer_derived_provider_contract(self):
        from narrowcti.adapters.opencti.graph_lookup import OpenCTIGraphLookup

        lookup = OpenCTIGraphLookup(type("Client", (), {"query": lambda *_: {}})())
        self.assertIsInstance(lookup, GraphProvider)

    def test_graph_deduplication_concrete_remains_core_but_helpers_are_domain_owned(self):
        import core.graph_deduplication as legacy_graph

        for name in domain_deduplication.__all__:
            self.assertIs(getattr(legacy_graph, name), getattr(domain_deduplication, name))

    def test_domain_graph_deduplication_has_no_runtime_boundary_imports(self):
        source = (ROOT / "src/narrowcti/domain/graph/deduplication.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        forbidden = ("core", "connectors", "gateway", "exporters", "infrastructure", "adapters")
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertFalse(
            [name for name in imported if name.split(".")[0] in forbidden],
            imported,
        )

    def test_legacy_and_canonical_graph_modules_share_objects_legacy_first(self):
        self._assert_subprocess(
            """
import core.opencti_graph_lookup as legacy_lookup
import core.opencti_deduplication as legacy_dedup
import narrowcti.adapters.opencti.graph_lookup as canonical_lookup
import narrowcti.adapters.opencti.deduplication as canonical_dedup
assert legacy_lookup.OpenCTIGraphLookup is canonical_lookup.OpenCTIGraphLookup
assert legacy_lookup.CompositeGraphLookup is canonical_lookup.CompositeGraphLookup
assert legacy_dedup.OpenCTIArtifactLookup is canonical_dedup.OpenCTIArtifactLookup
assert legacy_dedup.CompositeArtifactDeduplication is canonical_dedup.CompositeArtifactDeduplication
"""
        )

    def test_legacy_and_canonical_graph_modules_share_objects_canonical_first(self):
        self._assert_subprocess(
            """
import narrowcti.adapters.opencti.graph_lookup as canonical_lookup
import narrowcti.adapters.opencti.deduplication as canonical_dedup
import core.opencti_graph_lookup as legacy_lookup
import core.opencti_deduplication as legacy_dedup
assert legacy_lookup.OpenCTIGraphLookup is canonical_lookup.OpenCTIGraphLookup
assert legacy_lookup.CompositeGraphLookup is canonical_lookup.CompositeGraphLookup
assert legacy_dedup.OpenCTIArtifactLookup is canonical_dedup.OpenCTIArtifactLookup
assert legacy_dedup.CompositeArtifactDeduplication is canonical_dedup.CompositeArtifactDeduplication
"""
        )

    def test_legacy_lookup_surface_is_fully_reexported(self):
        import core.opencti_graph_lookup as legacy_lookup
        import narrowcti.adapters.opencti.graph_lookup as canonical_lookup

        self.assertEqual(set(canonical_lookup.__all__), set(legacy_lookup.__all__))
        for name in canonical_lookup.__all__:
            self.assertIs(getattr(legacy_lookup, name), getattr(canonical_lookup, name))

    def test_artifact_dedup_surface_is_fully_reexported(self):
        import core.opencti_deduplication as legacy_dedup
        import narrowcti.adapters.opencti.deduplication as canonical_dedup

        for name in canonical_dedup.__all__:
            self.assertIs(getattr(legacy_dedup, name), getattr(canonical_dedup, name))

    @staticmethod
    def _assert_subprocess(code: str):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{ROOT / 'src'};{ROOT}"
        subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env=env,
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
