import unittest
from unittest.mock import patch

from gateway.opencti_relationship_audit import (
    coverage_summary,
    normalize_quadrants,
    object_ref,
    parse_args,
    quadrant_for_object,
    summarize_relationships,
)


class OpenCTIRelationshipAuditTests(unittest.TestCase):
    def test_classifies_opencti_objects_into_diamond_quadrants(self):
        self.assertEqual(
            "adversary",
            quadrant_for_object({"entity_type": "Intrusion-Set"}),
        )
        self.assertEqual(
            "capability",
            quadrant_for_object({"entity_type": "Attack-Pattern"}),
        )
        self.assertEqual(
            "infrastructure",
            quadrant_for_object({"entity_type": "IPv4-Addr"}),
        )
        self.assertEqual(
            "victimology",
            quadrant_for_object({"entity_type": "Sector"}),
        )
        self.assertEqual("other", quadrant_for_object({"entity_type": "Report"}))

    def test_summarizes_inbound_and_outbound_relationships_for_target(self):
        target = {
            "id": "infra--1",
            "standard_id": "infrastructure--1",
            "entity_type": "Infrastructure",
            "name": "MISP ip-port 137.184.181.252",
        }
        relationships = {
            "inbound": [
                {
                    "relationship_type": "uses",
                    "from": {
                        "id": "malware--1",
                        "entity_type": "Malware",
                        "name": "Lorenz",
                    },
                    "to": target,
                }
            ],
            "outbound": [
                {
                    "relationship_type": "related-to",
                    "from": target,
                    "to": {
                        "id": "attack-pattern--1",
                        "entity_type": "Attack-Pattern",
                        "name": "Proxy",
                        "x_mitre_id": "T1090",
                    },
                },
                {
                    "relationship_type": "targets",
                    "from": target,
                    "to": {
                        "id": "sector--1",
                        "entity_type": "Sector",
                        "name": "Finance",
                    },
                },
            ],
        }

        summary = summarize_relationships(
            target,
            relationships,
            expected_quadrants=("capability", "victimology"),
            require_kill_chain=True,
        )

        self.assertTrue(summary["found"])
        self.assertEqual(3, summary["relationship_count"])
        self.assertEqual(2, summary["outbound_count"])
        self.assertEqual(1, summary["inbound_count"])
        self.assertEqual(
            {
                "adversary": 0,
                "capability": 2,
                "infrastructure": 0,
                "victimology": 1,
                "other": 0,
            },
            summary["diamond_quadrant_counts"],
        )
        self.assertEqual(["T1090 Proxy"], summary["kill_chain_attack_patterns"])
        self.assertEqual(
            {
                "status": "pass",
                "expected_quadrants": ["capability", "victimology"],
                "present_quadrants": ["capability", "victimology"],
                "missing_quadrants": [],
                "kill_chain_required": True,
                "kill_chain_present": True,
            },
            summary["coverage"],
        )
        self.assertEqual(
            {
                "direction": "outbound",
                "relationship_type": "related-to",
                "from": "Infrastructure:MISP ip-port 137.184.181.252",
                "to": "Attack-Pattern:Proxy",
            },
            summary["sample_relationships"][0],
        )

    def test_formats_observable_object_refs(self):
        self.assertEqual(
            "IPv4-Addr:203.0.113.10",
            object_ref(
                {
                    "entity_type": "IPv4-Addr",
                    "observable_value": "203.0.113.10",
                }
            ),
        )

    def test_reports_missing_expected_quadrants(self):
        coverage = coverage_summary(
            {"adversary": 0, "capability": 3, "infrastructure": 1, "victimology": 0},
            ["T1090 Proxy"],
            expected_quadrants="adversary,capability,infrastructure,victimology",
            require_kill_chain=True,
        )

        self.assertEqual("needs-evidence", coverage["status"])
        self.assertEqual(["adversary", "victimology"], coverage["missing_quadrants"])
        self.assertTrue(coverage["kill_chain_present"])

    def test_normalizes_expected_quadrants(self):
        self.assertEqual(
            ("adversary", "capability"),
            normalize_quadrants(" adversary,capability,invalid,adversary "),
        )

    def test_accepts_audit_target_from_environment(self):
        with patch.dict(
            "os.environ",
            {
                "NARROWCTI_OPENCTI_AUDIT_TYPE": "infrastructure",
                "NARROWCTI_OPENCTI_AUDIT_SEARCH": "MISP ip-port 137.184.181.252",
                "NARROWCTI_OPENCTI_AUDIT_FIRST": "80",
                "NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE": "state/audit.json",
                "NARROWCTI_OPENCTI_AUDIT_EXPECTED_QUADRANTS": "capability,infrastructure",
                "NARROWCTI_OPENCTI_AUDIT_REQUIRE_KILL_CHAIN": "true",
            },
        ):
            args = parse_args([])

        self.assertEqual("infrastructure", args.type)
        self.assertEqual("MISP ip-port 137.184.181.252", args.search)
        self.assertEqual(80, args.first)
        self.assertEqual("state/audit.json", args.output_file)
        self.assertEqual("capability,infrastructure", args.expected_quadrants)
        self.assertTrue(args.require_kill_chain)


if __name__ == "__main__":
    unittest.main()
