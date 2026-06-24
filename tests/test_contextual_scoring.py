import unittest

from core.contextual_scoring import build_contextual_score_evidence


class ContextualScoringTests(unittest.TestCase):
    def test_builds_dry_run_contextual_score_from_graph_categories(self):
        evidence = build_contextual_score_evidence(
            40,
            {
                "accepted_count": 4,
                "accepted": [
                    candidate("threat_actor", "APT Example", "threat-actor"),
                    candidate("malware", "LummaC2", "malware"),
                    candidate("attack_pattern", "T1059", "attack-pattern"),
                    candidate("target_sector", "Finance", "identity"),
                ],
            },
        )

        self.assertEqual("v0.7.0-dev", evidence["version"])
        self.assertEqual("dry-run", evidence["mode"])
        self.assertFalse(evidence["applied_to_decision"])
        self.assertEqual(40, evidence["base_score"])
        self.assertEqual(76, evidence["contextual_score"])
        self.assertEqual(36, evidence["score_delta"])
        self.assertEqual(60, evidence["raw_impact_total"])
        self.assertEqual(0.6, evidence["impact_ratio"])
        self.assertEqual(
            {"sector": 1, "threat": 1, "toolbox": 1, "ttp": 1},
            evidence["category_counts"],
        )
        self.assertEqual(4, evidence["adjustment_count"])

    def test_caps_impact_and_never_decreases_score(self):
        evidence = build_contextual_score_evidence(
            80,
            {
                "accepted": [
                    candidate("threat_actor", "APT Example", "threat-actor"),
                    candidate("malware", "LummaC2", "malware"),
                    candidate("attack_pattern", "T1059", "attack-pattern"),
                ],
            },
            category_impacts={"threat": 80, "toolbox": 80, "ttp": 80},
            max_impact=100,
        )

        self.assertTrue(evidence["capped"])
        self.assertEqual(240, evidence["raw_impact_total"])
        self.assertEqual(100, evidence["capped_impact_total"])
        self.assertEqual(100, evidence["contextual_score"])

    def test_deduplicates_repeated_category_entity_value_matches(self):
        evidence = build_contextual_score_evidence(
            50,
            {
                "accepted": [
                    candidate("attack_pattern", "T1059", "attack-pattern"),
                    candidate("attack_pattern", "T1059", "attack-pattern"),
                    candidate("attack_pattern", "T1105", "attack-pattern"),
                ],
            },
        )

        self.assertEqual(2, evidence["adjustment_count"])
        self.assertEqual(1, evidence["deduplicated_adjustment_count"])
        self.assertEqual({"ttp": 2}, evidence["category_counts"])

    def test_disabled_mode_preserves_base_score(self):
        evidence = build_contextual_score_evidence(
            "bad-score",
            {"accepted_count": 1, "accepted": [candidate("malware", "Tool", "malware")]},
            mode="audit",
            enabled=False,
        )

        self.assertEqual("disabled", evidence["status"])
        self.assertEqual(50, evidence["base_score"])
        self.assertEqual(50, evidence["contextual_score"])
        self.assertEqual(0, evidence["adjustment_count"])
        self.assertEqual(1, evidence["accepted_candidate_count"])


def candidate(entity_type, value, stix_object_type):
    return {
        "entity_type": entity_type,
        "value": value,
        "name": value,
        "stix_object_type": stix_object_type,
        "relationship_type": "related-to",
        "source_field": "fixture",
        "confidence": 70,
        "relationship_confidence": 70,
    }


if __name__ == "__main__":
    unittest.main()
