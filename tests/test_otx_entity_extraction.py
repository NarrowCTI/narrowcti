import unittest

from connectors.otx.entity_extraction import (
    extract_otx_entities,
    normalize_attack_ids,
    normalize_cve_ids,
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
                "cves": ["CVE-2024-12345", "reference to cve-2023-9999"],
                "industries": "Finance, Healthcare",
                "target_countries": ["BR", "US"],
                "author_name": "AlienVault Research",
                "id": "pulse-1",
                "created": "2026-04-01T00:00:00Z",
                "modified": "2026-04-03T00:00:00Z",
                "upvotes_count": 7,
                "downvotes_count": 1,
                "TLP": "TLP:AMBER",
                "references": [
                    "https://example.com/report",
                    {"url": "https://vendor.example/ioc", "source_name": "Vendor"},
                ],
                "indicators": [
                    {
                        "type": "domain",
                        "indicator": "one.example",
                        "first_seen": "2026-04-01T10:00:00Z",
                        "last_seen": "2026-04-02T10:00:00Z",
                    },
                    {
                        "type": "url",
                        "indicator": "https://two.example/a",
                        "first_seen": "2026-04-02T10:00:00Z",
                        "last_seen": "2026-04-05T10:00:00Z",
                    },
                    {
                        "id": "indicator-yara-1",
                        "type": "YARA",
                        "indicator": "rule SuspiciousRule { condition: true }",
                        "description": "Suspicious YARA rule",
                    },
                ],
                "tags": ["credential theft", "T1059"],
            }
        )

        self.assertEqual(["APT Example"], entities["adversaries"])
        self.assertEqual(["LummaC2", "Stealc"], entities["malware_families"])
        self.assertEqual(["T1059", "T1105", "T1059.001"], entities["attack_ids"])
        self.assertEqual(["CVE-2024-12345", "CVE-2023-9999"], entities["vulnerabilities"])
        self.assertEqual(["Finance", "Healthcare"], entities["industries"])
        self.assertEqual(["BR", "US"], entities["targeted_countries"])
        self.assertEqual(["AlienVault Research"], entities["authors"])
        self.assertEqual("pulse-1", entities["lifecycle"]["pulse_id"])
        self.assertEqual("2026-04-03T00:00:00Z", entities["lifecycle"]["modified"])
        self.assertEqual(7, entities["vote_summary"]["upvotes"])
        self.assertEqual(
            "2026-04-01T10:00:00Z",
            entities["indicator_observation_window"]["first_seen_min"],
        )
        self.assertEqual(
            "2026-04-05T10:00:00Z",
            entities["indicator_observation_window"]["last_seen_max"],
        )
        self.assertEqual(2, len(entities["observables"]))
        self.assertEqual("domain-name", entities["observables"][0]["observable_type"])
        self.assertEqual("url", entities["observables"][1]["observable_type"])
        self.assertEqual(1, len(entities["detection_rules"]))
        self.assertEqual("yara", entities["detection_rules"][0]["rule_type"])
        self.assertEqual(
            "rule SuspiciousRule { condition: true }",
            entities["detection_rules"][0]["pattern"],
        )
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
        self.assertEqual(2, entities["counts"]["vulnerabilities"])
        self.assertEqual(2, entities["counts"]["observables"])
        self.assertEqual(1, entities["counts"]["detection_rules"])
        self.assertIn(
            {
                "entity_type": "observable",
                "value": "one.example",
                "source_field": "indicators",
                "confidence": 65,
                "attributes": {
                    "observable_type": "domain-name",
                    "indicator_type": "domain",
                    "indicator_id": None,
                    "hash_algorithm": None,
                    "created": None,
                    "first_seen": "2026-04-01T10:00:00Z",
                    "last_seen": "2026-04-02T10:00:00Z",
                },
            },
            entities["records"],
        )
        self.assertIn(
            {
                "entity_type": "detection_rule",
                "value": "Suspicious YARA rule",
                "source_field": "indicators",
                "confidence": 70,
                "attributes": {
                    "rule_type": "yara",
                    "pattern_type": "yara",
                    "pattern": "rule SuspiciousRule { condition: true }",
                    "indicator_type": "YARA",
                    "indicator_id": "indicator-yara-1",
                    "created": None,
                    "first_seen": None,
                    "last_seen": None,
                },
            },
            entities["records"],
        )

    def test_normalizes_attack_ids_from_mixed_strings(self):
        self.assertEqual(
            ["T1059", "T1105", "T1566.001"],
            normalize_attack_ids("t1059, technique T1105, subtechnique T1566.001"),
        )

    def test_normalizes_cve_ids_from_nested_values(self):
        self.assertEqual(
            ["CVE-2024-12345", "CVE-2023-9999"],
            normalize_cve_ids(
                [
                    {"value": "CVE-2024-12345"},
                    "seen in https://example.test/CVE-2023-9999",
                    "cve-2024-12345",
                ]
            ),
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
