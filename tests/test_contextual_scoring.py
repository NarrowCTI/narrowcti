import unittest

from core.contextual_scoring import (
    build_contextual_score_evidence,
    contextual_scoring_config_from_settings,
    finalize_contextual_score_evidence,
    normalize_contextual_scoring_max_impact,
    normalize_contextual_scoring_mode,
    parse_contextual_scoring_impacts,
)


class ContextualScoringTests(unittest.TestCase):
    def test_builds_shadow_contextual_score_from_graph_categories(self):
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

        self.assertEqual("v1.0.0", evidence["version"])
        self.assertEqual("shadow", evidence["mode"])
        self.assertFalse(evidence["applied_to_decision"])
        self.assertEqual(40, evidence["base_score"])
        self.assertEqual(76, evidence["contextual_score"])
        self.assertEqual(40, evidence["decision_score"])
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
        self.assertEqual(50, evidence["decision_score"])
        self.assertEqual(0, evidence["adjustment_count"])
        self.assertEqual(1, evidence["accepted_candidate_count"])

    def test_enforce_mode_uses_contextual_score_for_decision(self):
        evidence = build_contextual_score_evidence(
            40,
            {
                "accepted": [
                    candidate("threat_actor", "APT Example", "threat-actor"),
                    candidate("attack_pattern", "T1059", "attack-pattern"),
                ],
            },
            mode="enforce",
        )

        self.assertTrue(evidence["applied_to_decision"])
        self.assertEqual(61, evidence["contextual_score"])
        self.assertEqual(61, evidence["decision_score"])

    def test_finalization_records_when_enforce_was_not_used(self):
        evidence = build_contextual_score_evidence(
            40,
            {"accepted": [candidate("threat_actor", "APT Example", "threat-actor")]},
            mode="enforce",
        )

        finalized = finalize_contextual_score_evidence(
            evidence,
            40,
            "drop",
            "tlp not allowed: red",
        )

        self.assertTrue(finalized["configured_to_apply"])
        self.assertFalse(finalized["applied_to_decision"])
        self.assertEqual(40, finalized["decision_score"])
        self.assertEqual("drop", finalized["decision_action"])
        self.assertEqual("tlp not allowed: red", finalized["decision_reason"])

    def test_off_mode_emits_no_adjustments(self):
        evidence = build_contextual_score_evidence(
            40,
            {"accepted": [candidate("malware", "Tool", "malware")]},
            mode="off",
        )

        self.assertEqual("off", evidence["status"])
        self.assertEqual(40, evidence["decision_score"])
        self.assertEqual([], evidence["adjustments"])

    def test_normalizes_legacy_shadow_aliases(self):
        self.assertEqual("shadow", normalize_contextual_scoring_mode("dry-run"))
        self.assertEqual("shadow", normalize_contextual_scoring_mode("audit"))
        self.assertEqual("off", normalize_contextual_scoring_mode("disabled"))

    def test_rejects_unknown_mode(self):
        with self.assertRaisesRegex(ValueError, "off, shadow or enforce"):
            normalize_contextual_scoring_mode("automatic")

    def test_rejects_out_of_range_max_impact(self):
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            normalize_contextual_scoring_max_impact(101)

    def test_parses_configured_category_impacts(self):
        self.assertEqual(
            {"threat": 25, "ttp": 10},
            parse_contextual_scoring_impacts("threat:25,ttp:10"),
        )

    def test_rejects_unknown_impact_category(self):
        with self.assertRaisesRegex(ValueError, "unknown contextual scoring category"):
            parse_contextual_scoring_impacts("unknown:10")

    def test_builds_config_from_settings(self):
        settings = type(
            "Settings",
            (),
            {
                "contextual_scoring_mode": "enforce",
                "contextual_scoring_impacts": {"threat": 30},
                "contextual_scoring_max_impact": 80,
            },
        )()

        self.assertEqual(
            {
                "mode": "enforce",
                "category_impacts": {"threat": 30},
                "max_impact": 80,
            },
            contextual_scoring_config_from_settings(settings),
        )


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
