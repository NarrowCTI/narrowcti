"""PR-14 contracts for STIX/compiler/OpenCTI boundaries."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import exporters.stix_builder as legacy_builder
from exporters.opencti import send_bundle as legacy_send_bundle
from narrowcti.adapters.opencti import exporter as canonical_exporter
from narrowcti.adapters.opencti.stix_profile import (
    OPENCTI_CUSTOM_SDO_TYPES,
    OPENCTI_EXTENSION_DEFINITION_ID,
)
from narrowcti.adapters.stix import identifiers, patterns
from narrowcti.adapters.stix.serializer import build_report_bundle as canonical_report_bundle
from narrowcti.application.compiler import compile_graph_semantics


ROOT = Path(__file__).resolve().parents[1]


class StixBoundaryTests(unittest.TestCase):
    @staticmethod
    def _imports(path: Path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
        return imports

    @staticmethod
    def _assert_subprocess(code: str) -> None:
        env = os.environ.copy()
        paths = [str(ROOT / "src"), str(ROOT)]
        existing = env.get("PYTHONPATH")
        if existing:
            paths.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(paths)
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, check=True)

    def test_indicator_pattern_is_canonical_and_legacy_compatible(self):
        self.assertIs(legacy_builder.indicator_pattern, patterns.indicator_pattern)
        self.assertEqual(
            "[domain-name:value = 'example\\'.com']",
            patterns.indicator_pattern({"indicator": "example'.com", "type": "domain"}),
        )

    def test_deterministic_identifier_symbols_are_canonical(self):
        self.assertIs(legacy_builder.deterministic_graph_object_id, identifiers.deterministic_graph_object_id)
        self.assertIs(legacy_builder.deterministic_identity_id, identifiers.deterministic_identity_id)
        self.assertIs(legacy_builder.deterministic_report_id, identifiers.deterministic_report_id)

    def test_generic_serializer_has_no_opencti_runtime_names(self):
        path = ROOT / "src" / "narrowcti" / "adapters" / "stix" / "serializer.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertNotIn("pycti", names)
        self.assertFalse(any(name.startswith("OPENCTI_") for name in names))
        self.assertNotIn("send_bundle", names)

    def test_pr14_import_boundaries_are_explicit(self):
        compiler_root = ROOT / "src" / "narrowcti" / "application" / "compiler"
        stix_root = ROOT / "src" / "narrowcti" / "adapters" / "stix"
        dedup_path = ROOT / "src" / "narrowcti" / "adapters" / "opencti" / "deduplication.py"
        compiler_imports = set().union(*(self._imports(path) for path in compiler_root.glob("*.py")))
        stix_imports = set().union(*(self._imports(path) for path in stix_root.glob("*.py")))
        dedup_imports = self._imports(dedup_path)
        self.assertFalse(any(name.startswith("stix2") for name in compiler_imports))
        self.assertFalse(any(name.startswith("pycti") for name in compiler_imports))
        self.assertFalse(any(name.startswith("gateway") for name in compiler_imports))
        self.assertFalse(any(name.startswith("exporters") for name in compiler_imports))
        self.assertFalse(any(name.startswith("connectors") for name in compiler_imports))
        self.assertFalse(any(name.startswith("pycti") for name in stix_imports))
        self.assertFalse(any(name.startswith("gateway") for name in stix_imports))
        self.assertNotIn("exporters.stix_builder", dedup_imports)
        self.assertIn("narrowcti.adapters.stix.patterns", dedup_imports)

    def test_compiler_ir_is_semantic_and_deduplicates_keys(self):
        result = compile_graph_semantics(
            [
                {
                    "fingerprint": "candidate-1",
                    "entity_type": "malware",
                    "display_name": "Example Malware",
                    "value": "example",
                    "source_key": "malware:example",
                    "target_key": "attack-pattern:T1003",
                    "relationship_type": "uses",
                    "relationship_confidence": 80,
                },
                {
                    "fingerprint": "candidate-1",
                    "entity_type": "malware",
                    "display_name": "duplicate",
                },
            ]
        )
        self.assertEqual(1, len(result.objects))
        self.assertEqual(1, len(result.relationships))
        self.assertEqual(("candidate-1",), result.skipped)
        self.assertEqual("malware", result.objects[0].semantic_type)
        self.assertNotIn("stix2", result.objects[0].attributes)

    def test_opencti_profile_is_not_generic_stix(self):
        self.assertIn("channel", OPENCTI_CUSTOM_SDO_TYPES)
        self.assertTrue(OPENCTI_EXTENSION_DEFINITION_ID.startswith("extension-definition--"))
        serializer_source = (
            ROOT / "src" / "narrowcti" / "adapters" / "stix" / "serializer.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("OPENCTI_EXTENSION_DEFINITION_ID", serializer_source)
        self.assertNotIn("ExtensionDefinition", serializer_source)

    def test_opencti_exporter_preserves_legacy_entrypoint_identity(self):
        self.assertIs(legacy_send_bundle, canonical_exporter.send_bundle)
        self.assertIs(
            canonical_exporter.OpenCTIImportRejectedError,
            __import__("exporters.opencti", fromlist=["OpenCTIImportRejectedError"])
            .OpenCTIImportRejectedError,
        )

    def test_opencti_exporter_identity_legacy_first(self):
        self._assert_subprocess(
            """
import exporters.opencti as legacy
import narrowcti.adapters.opencti.exporter as canonical
assert legacy.send_bundle is canonical.send_bundle
assert legacy.OpenCTIImportRejectedError is canonical.OpenCTIImportRejectedError
"""
        )

    def test_opencti_exporter_identity_canonical_first(self):
        self._assert_subprocess(
            """
import narrowcti.adapters.opencti.exporter as canonical
import exporters.opencti as legacy
assert legacy.send_bundle is canonical.send_bundle
assert legacy.OpenCTIImportRejectedError is canonical.OpenCTIImportRejectedError
"""
        )

    def test_generic_report_bundle_matches_legacy_shape(self):
        indicators = [{"indicator": "example.org", "type": "domain"}]
        legacy_bundle, legacy_count = legacy_builder.build_report_bundle(
            "Parity report",
            "Parity description",
            70,
            indicators=indicators,
            published_at="2022-01-27T21:00:00Z",
        )
        canonical_bundle, canonical_count = canonical_report_bundle(
            "Parity report",
            "Parity description",
            70,
            indicators=indicators,
            published_at="2022-01-27T21:00:00Z",
        )
        self.assertEqual(legacy_count, canonical_count)
        legacy = json.loads(legacy_bundle.serialize())
        canonical = json.loads(canonical_bundle.serialize())
        stable_types = {"identity", "report"}
        self.assertEqual(
            {(item["type"], item["id"]) for item in legacy["objects"] if item["type"] in stable_types},
            {(item["type"], item["id"]) for item in canonical["objects"] if item["type"] in stable_types},
        )
        self.assertEqual(
            [(item["type"], item.get("name"), item.get("pattern")) for item in legacy["objects"]],
            [(item["type"], item.get("name"), item.get("pattern")) for item in canonical["objects"]],
        )


if __name__ == "__main__":
    unittest.main()
