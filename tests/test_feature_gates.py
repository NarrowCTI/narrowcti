import unittest

from gateway.feature_gates import build_feature_gate_state


class FeatureGateTests(unittest.TestCase):
    def test_defaults_to_evaluation_capabilities(self):
        state = build_feature_gate_state("")

        self.assertEqual("evaluation", state.edition)
        self.assertTrue(state.known_edition)
        self.assertFalse(state.license_configured)
        self.assertFalse(state.enforcement_enabled)
        self.assertIn("source.otx", state.enabled_capabilities)
        self.assertIn("graph.export.audit", state.enabled_capabilities)
        self.assertIn("reports.support_diagnostics", state.enabled_capabilities)

    def test_requested_capabilities_override_edition_defaults(self):
        state = build_feature_gate_state(
            "Enterprise",
            license_file="/licenses/customer.lic",
            enforcement_enabled=True,
            requested_capabilities=[
                "source.otx",
                "source.otx",
                "REPORTS.SUPPORT-DIAGNOSTICS",
                "GRAPH.LOOKUP.OPENCTI",
            ],
        )

        self.assertEqual("enterprise", state.edition)
        self.assertTrue(state.license_configured)
        self.assertTrue(state.enforcement_enabled)
        self.assertEqual(
            (
                "source.otx",
                "reports.support_diagnostics",
                "graph.lookup.opencti",
            ),
            state.enabled_capabilities,
        )

    def test_unknown_capabilities_are_reported_without_being_enabled(self):
        state = build_feature_gate_state(
            "professional",
            requested_capabilities=["source.misp", "unknown.capability"],
        )

        self.assertEqual(("source.misp",), state.enabled_capabilities)
        self.assertEqual(("unknown.capability",), state.unknown_capabilities)

    def test_unknown_edition_is_visible_and_has_no_default_capabilities(self):
        state = build_feature_gate_state("partner")

        self.assertEqual("partner", state.edition)
        self.assertFalse(state.known_edition)
        self.assertEqual((), state.enabled_capabilities)


if __name__ == "__main__":
    unittest.main()
