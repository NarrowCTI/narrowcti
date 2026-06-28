import unittest
from unittest.mock import patch

from gateway.opencti_relationship_audit import (
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

        summary = summarize_relationships(target, relationships)

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

    def test_accepts_audit_target_from_environment(self):
        with patch.dict(
            "os.environ",
            {
                "NARROWCTI_OPENCTI_AUDIT_TYPE": "infrastructure",
                "NARROWCTI_OPENCTI_AUDIT_SEARCH": "MISP ip-port 137.184.181.252",
                "NARROWCTI_OPENCTI_AUDIT_FIRST": "80",
                "NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE": "state/audit.json",
            },
        ):
            args = parse_args([])

        self.assertEqual("infrastructure", args.type)
        self.assertEqual("MISP ip-port 137.184.181.252", args.search)
        self.assertEqual(80, args.first)
        self.assertEqual("state/audit.json", args.output_file)


if __name__ == "__main__":
    unittest.main()
