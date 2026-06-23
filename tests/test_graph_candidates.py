import unittest

from core.graph_candidates import (
    build_graph_candidates,
    candidate_fingerprint,
    graph_candidate_from_record,
)
from core.graph_evidence import build_graph_evidence


class GraphCandidateTests(unittest.TestCase):
    def test_builds_graph_candidates_from_evidence_records(self):
        candidates = build_graph_candidates(
            {
                "version": "v0.7.0-dev",
                "source_key": "alienvault:otx",
                "external_id": "pulse-1",
                "title": "Technique pulse",
                "records": [
                    {
                        "entity_type": "attack_pattern",
                        "value": "T1059",
                        "display_name": "Command and Scripting Interpreter",
                        "stix_object_type": "attack-pattern",
                        "relationship_type": "uses",
                        "source_key": "alienvault:otx",
                        "source_name": "mitre-attack",
                        "source_field": "mitre_attack.resolved",
                        "confidence": 90,
                        "attributes": {
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                        },
                    }
                ],
            }
        )

        self.assertEqual("v0.7.0-dev", candidates.version)
        self.assertEqual("alienvault:otx", candidates.source_key)
        self.assertEqual("pulse-1", candidates.external_id)
        self.assertEqual(1, candidates.candidate_count)
        self.assertEqual({"attack_pattern": 1}, candidates.counts)

        candidate = candidates.candidates[0]
        self.assertEqual("Command and Scripting Interpreter", candidate.name)
        self.assertEqual("attack-pattern", candidate.stix_object_type)
        self.assertEqual("uses", candidate.relationship_type)
        self.assertEqual(["execution"], candidate.attributes["tactics"])
        self.assertEqual(
            candidate_fingerprint(
                "alienvault:otx",
                "pulse-1",
                "attack_pattern",
                "attack-pattern",
                "T1059",
            ),
            candidate.fingerprint,
        )

        candidate_dict = candidate.to_dict()
        self.assertEqual("pulse-1", candidate_dict["external_id"])
        self.assertEqual("Technique pulse", candidate_dict["title"])
        self.assertEqual(
            "Command and Scripting Interpreter",
            candidate_dict["display_name"],
        )

    def test_builds_mitre_reference_candidates_from_evidence(self):
        evidence = build_graph_evidence(
            {
                "mitre_attack": {
                    "available": True,
                    "resolved": [
                        {
                            "attack_id": "T1059",
                            "found": True,
                            "name": "Command and Scripting Interpreter",
                            "tactics": ["execution"],
                            "stix_id": "attack-pattern--1",
                            "url": "https://attack.mitre.org/techniques/T1059/",
                            "platforms": ["Windows"],
                            "data_sources": ["Process: Process Creation"],
                            "detection": "Monitor process execution.",
                        }
                    ],
                }
            },
            source_key="alienvault:otx",
            external_id="pulse-1",
            title="Technique pulse",
        )

        candidates = build_graph_candidates(evidence)

        self.assertEqual(6, candidates.candidate_count)
        self.assertEqual(1, candidates.counts["attack_pattern"])
        self.assertEqual(1, candidates.counts["attack_tactic"])
        self.assertEqual(1, candidates.counts["attack_platform"])
        self.assertEqual(1, candidates.counts["attack_data_source"])
        self.assertEqual(1, candidates.counts["detection_guidance"])
        self.assertEqual(1, candidates.counts["external_reference"])

        attack_pattern = next(
            candidate
            for candidate in candidates.candidates
            if candidate.entity_type == "attack_pattern"
        )
        self.assertEqual(
            [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                }
            ],
            attack_pattern.attributes["external_references"],
        )
        self.assertEqual(
            [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            attack_pattern.attributes["kill_chain_phases"],
        )

        detection = next(
            candidate
            for candidate in candidates.candidates
            if candidate.entity_type == "detection_guidance"
        )
        self.assertEqual("note", detection.stix_object_type)
        self.assertEqual("Detection guidance for T1059", detection.name)
        self.assertEqual("Monitor process execution.", detection.value)

    def test_filters_candidates_by_confidence_and_type(self):
        candidates = build_graph_candidates(
            {
                "source_key": "misp:misp",
                "records": [
                    {
                        "entity_type": "tag",
                        "value": "ransomware",
                        "stix_object_type": "label",
                        "confidence": 35,
                    },
                    {
                        "entity_type": "marking",
                        "value": "green",
                        "stix_object_type": "marking-definition",
                        "confidence": 80,
                    },
                    {
                        "entity_type": "collector",
                        "value": "misp",
                        "stix_object_type": "identity",
                        "confidence": 80,
                    },
                ],
            },
            min_confidence=50,
            excluded_stix_object_types={"marking-definition"},
        )

        self.assertEqual(1, candidates.candidate_count)
        self.assertEqual("collector", candidates.candidates[0].entity_type)

    def test_skips_malformed_records_and_clamps_confidence(self):
        candidates = build_graph_candidates(
            {
                "source_key": "alienvault:otx",
                "records": [
                    {},
                    "not a record",
                    {
                        "entity_type": "malware",
                        "value": "ExampleMalware",
                        "stix_object_type": "malware",
                        "relationship_type": "",
                        "confidence": "250",
                    },
                ],
            }
        )

        self.assertEqual(1, candidates.candidate_count)
        candidate = candidates.candidates[0]
        self.assertEqual(100, candidate.confidence)
        self.assertEqual("related-to", candidate.relationship_type)

    def test_record_without_required_fields_does_not_build_candidate(self):
        self.assertIsNone(
            graph_candidate_from_record(
                {
                    "entity_type": "malware",
                    "value": "",
                    "stix_object_type": "malware",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
