import unittest

from connectors.otx.entity_extraction import (
    extract_otx_entities,
    normalize_attack_ids,
    normalize_references,
    normalize_tlp,
)


class OTXEntityExtractionTests(unittest.TestCase):
    def test_extracts_enterprise_entity_hints_from_otx_payload(self):
        entities = extract_otx_entities(
            {
                "adversary": "APT Example",
                "malware_families": [
                    "LummaC2",
                    {"display_name": "Stealc", "id": "malware-1"},
                ],
                "attack_ids": ["T1059", "Uses T1105 and T1059.001"],
                "industries": "Finance, Healthcare",
                "target_countries": ["BR", "US"],
                "TLP": "TLP:AMBER",
                "references": [
                    "https://example.com/report",
                    {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
                ],
                "tags": ["credential theft", "T1059"],
            }
        )

        self.assertEqual(["APT Example"], entities["adversaries"])
        self.assertEqual(["LummaC2", "Stealc"], entities["malware_families"])
        self.assertEqual(["T1059", "T1105", "T1059.001"], entities["attack_ids"])
        self.assertEqual(["Finance", "Healthcare"], entities["industries"])
        self.assertEqual(["BR", "US"], entities["targeted_countries"])
        self.assertEqual(["amber"], entities["tlp"])
        self.assertEqual(
            {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
            entities["references"][1],
        )
        self.assertIn(
            {
                "entity_type": "attack_pattern",
                "value": "T1059.001",
                "source_field": "attack_ids",
                "confidence": 70,
            },
            entities["records"],
        )
        self.assertEqual(3, entities["counts"]["attack_ids"])

    def test_normalizes_attack_ids_from_mixed_strings(self):
        self.assertEqual(
            ["T1059", "T1105", "T1566.001"],
            normalize_attack_ids("t1059, technique T1105, subtechnique T1566.001"),
        )

    def test_normalizes_tlp_alias_fields(self):
        self.assertEqual(["green"], normalize_tlp({"tlp_marking": "tlp:green"}))

    def test_normalizes_reference_strings_and_dicts(self):
        self.assertEqual(
            [
                {"url": "https://example.com/report", "source_name": "example.com"},
                {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
            ],
            normalize_references(
                [
                    "https://example.com/report",
                    {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
