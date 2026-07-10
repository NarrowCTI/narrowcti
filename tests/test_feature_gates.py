import unittest

from gateway.feature_gates import build_feature_gate_state


class FeatureGateTests(unittest.TestCase):
    def test_defaults_to_open_source_capabilities(self):
        state = build_feature_gate_state()

        self.assertEqual("open_source", state.distribution_model)
        self.assertTrue(state.open_source)
        self.assertFalse(state.enforcement_enabled)
        self.assertIn("source.otx", state.enabled_capabilities)
        self.assertIn("graph.export.audit", state.enabled_capabilities)
        self.assertIn("reports.operational_validation", state.enabled_capabilities)
        self.assertIn("reports.support_diagnostics", state.enabled_capabilities)
        self.assertIn("graph.lookup.opencti", state.enabled_capabilities)
        self.assertIn("graph.export.controlled", state.enabled_capabilities)
        self.assertEqual((), state.disabled_capabilities)

    def test_requested_capabilities_are_visible_without_disabling_others(self):
        state = build_feature_gate_state(
            requested_capabilities=[
                "source.otx",
                "REPORTS.OPERATIONAL-VALIDATION",
                "source.otx",
                "REPORTS.SUPPORT-DIAGNOSTICS",
                "GRAPH.LOOKUP.OPENCTI",
            ],
        )

        self.assertEqual("open_source", state.distribution_model)
        self.assertFalse(state.enforcement_enabled)
        self.assertEqual(
            (
                "source.otx",
                "reports.operational_validation",
                "reports.support_diagnostics",
                "graph.lookup.opencti",
            ),
            state.requested_capabilities,
        )
        self.assertIn("source.misp", state.enabled_capabilities)
        self.assertIn("graph.export.controlled", state.enabled_capabilities)

    def test_unknown_capabilities_are_reported_without_being_enabled(self):
        state = build_feature_gate_state(
            requested_capabilities=["source.misp", "unknown.capability"],
        )

        self.assertIn("source.misp", state.enabled_capabilities)
        self.assertIn("source.otx", state.enabled_capabilities)
        self.assertEqual(("unknown.capability",), state.unknown_capabilities)


if __name__ == "__main__":
    unittest.main()
