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
        self.assertEqual(("mssp.multi_environment",), state.disabled_capabilities)

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

    def test_legacy_aliases_and_community_compatibility_are_preserved(self):
        state = build_feature_gate_state(
            requested_capabilities=[
                "reports.operational_validation",
                "reports.support_diagnostics",
                "mssp.multi_environment",
            ],
        )
        self.assertEqual(
            (
                "reports.operational_validation",
                "reports.support_diagnostics",
                "mssp.multi_environment",
            ),
            state.requested_capabilities,
        )
        self.assertIn("deployment.templates", state.enabled_capabilities)
        self.assertNotIn("mssp.multi_environment", state.enabled_capabilities)
        self.assertEqual(("mssp.multi_environment",), state.disabled_capabilities)

    def test_configuration_cannot_escalate_commercial_capabilities(self):
        state = build_feature_gate_state(
            requested_capabilities=[
                "validation.openaev",
                "ui.control_plane",
                "ingestion.scheduler",
                "environment.multi",
                "mssp.multi_tenant",
            ],
        )
        self.assertFalse(
            set(state.enabled_capabilities)
            & {
                "validation.openaev",
                "ui.control_plane",
                "ingestion.scheduler",
                "environment.multi",
                "mssp.multi_tenant",
            }
        )

    def test_legacy_dto_shape_remains_stable(self):
        state = build_feature_gate_state()
        self.assertEqual(
            (
                "distribution_model",
                "open_source",
                "enforcement_enabled",
                "available_capabilities",
                "enabled_capabilities",
                "disabled_capabilities",
                "requested_capabilities",
                "unknown_capabilities",
            ),
            tuple(state.to_dict()),
        )


if __name__ == "__main__":
    unittest.main()
