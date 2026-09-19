import ast
import importlib
import unittest
from pathlib import Path
from types import SimpleNamespace

from connectors.misp.processor import decision_metadata
from core.feed_contract import FeedCandidate, FeedSource
from narrowcti.adapters.sources.misp.context import extract_misp_context
from narrowcti.adapters.sources.misp.detection_rules import (
    extract_misp_detection_rules,
    sigma_rule_opencti_compatibility,
)
from narrowcti.adapters.sources.misp.entities import extract_misp_galaxies


ROOT = Path(__file__).resolve().parents[1]
MISP_SOURCE = FeedSource(name="MISP", source_type="external_import", provider="MISP")


class MISPExtractorTests(unittest.TestCase):
    def test_context_composes_source_specific_outputs(self):
        source = {
            "info": "Exploit CVE-2024-12345",
            "Attribute": [
                {
                    "type": "campaign-name",
                    "value": "Operation Example",
                    "uuid": "campaign-1",
                },
                {"type": "domain|ip", "value": "c2.example.test"},
            ],
        }

        context = extract_misp_context(source, tags=["cve:CVE-2023-99999"])

        self.assertEqual("CVE-2023-99999", context["misp_vulnerabilities"][0]["value"])
        self.assertEqual("Operation Example", context["misp_campaigns"][0]["value"])
        self.assertEqual("Attribute[1]", context["misp_infrastructure"][0]["source_field"])

    def test_canonical_extractors_preserve_first_seen_galaxy_order(self):
        event = {
            "Galaxy": {
                "type": "mitre-attack-pattern",
                "GalaxyCluster": [
                    {"uuid": "one", "value": "T1059"},
                    {"uuid": "one", "value": "T1059"},
                    {"uuid": "two", "value": "T1105"},
                ],
            }
        }

        records = extract_misp_galaxies(event)

        self.assertEqual(["T1059", "T1105"], [record["value"] for record in records])

    def test_detection_rules_keep_sigma_fail_closed_contract(self):
        event = {
            "Attribute": [
                {
                    "type": "sigma",
                    "value": "title: Example\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection",
                }
            ]
        }

        rules = extract_misp_detection_rules(event)

        self.assertEqual(1, len(rules))
        self.assertIn("opencti_indicator_compatible", rules[0])
        self.assertIsInstance(sigma_rule_opencti_compatibility(rules[0]["pattern"]), tuple)

    def test_decision_metadata_owns_source_and_tag_fallback(self):
        candidate_ref = FeedCandidate(
            source=MISP_SOURCE,
            external_id="event-1",
            title="Fallback event",
            tags=("cve:CVE-2023-99999",),
            raw={"id": "event-1", "tags": ["cve:CVE-2024-12345"]},
        )
        candidate = SimpleNamespace(event={}, score_details={})

        metadata = decision_metadata(candidate_ref, candidate)

        self.assertEqual(["cve:CVE-2024-12345"], metadata["tags"])
        self.assertEqual(
            ["CVE-2024-12345"],
            [item["value"] for item in metadata["misp_vulnerabilities"]],
        )

    def test_misp_adapter_modules_have_no_runtime_boundary_imports(self):
        package = ROOT / "src" / "narrowcti" / "adapters" / "sources" / "misp"
        forbidden = ("core", "connectors", "gateway", "exporters", "application")
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    self.assertFalse(
                        name == "narrowcti" or name.startswith("narrowcti.core."),
                        f"{path} imports forbidden canonical boundary {name}",
                    )
                    self.assertFalse(
                        any(name == prefix or name.startswith(f"{prefix}.") for prefix in forbidden),
                        f"{path} imports forbidden runtime boundary {name}",
                    )

    def test_processor_reexports_canonical_sigma_function(self):
        processor = importlib.import_module("connectors.misp.processor")
        detection_rules = importlib.import_module(
            "narrowcti.adapters.sources.misp.detection_rules"
        )

        self.assertIs(
            processor.sigma_rule_opencti_compatibility,
            detection_rules.sigma_rule_opencti_compatibility,
        )


if __name__ == "__main__":
    unittest.main()
