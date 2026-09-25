import unittest

from narrowcti.adapters.entitlements.community import (
    COMMUNITY_ENTITLED_CAPABILITIES,
    CommunityEntitlements,
)
from narrowcti.application.capabilities import (
    COMMUNITY_FUTURE_CAPABILITIES,
    COMMUNITY_CAPABILITY_NAMES,
    CapabilityRegistry,
)
from narrowcti.infrastructure.capabilities import COMMUNITY_IMPLEMENTED_CAPABILITIES
from narrowcti.ports.entitlements import EntitlementProvider


class CapabilityRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = CapabilityRegistry.default()

    def test_current_community_capabilities_remain_enabled(self):
        resolution = self.registry.resolve(
            implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
            entitled=CommunityEntitlements().granted_capabilities(),
        )
        self.assertEqual(tuple(sorted(COMMUNITY_CAPABILITY_NAMES)), resolution.enabled)
        self.assertEqual(tuple(sorted(COMMUNITY_CAPABILITY_NAMES)), resolution.implemented)
        self.assertEqual(tuple(sorted(COMMUNITY_ENTITLED_CAPABILITIES)), resolution.entitled)
        self.assertNotIn("mssp.multi_environment", resolution.enabled)

    def test_future_community_and_commercial_capabilities_are_not_enabled(self):
        resolution = self.registry.resolve(
            requested=["ui.basic", "source.explorer", "ingestion.run_once", "environment.multi"],
            implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
            entitled=CommunityEntitlements().granted_capabilities(),
        )
        self.assertEqual(
            ("ui.basic", "source.explorer", "ingestion.run_once", "environment.multi"),
            resolution.requested,
        )
        self.assertFalse(set(COMMUNITY_FUTURE_CAPABILITIES) & set(resolution.enabled))
        self.assertNotIn("environment.multi", resolution.enabled)

    def test_aliases_resolve_without_double_counting(self):
        resolution = self.registry.resolve(
            requested=["reports.operational", "reporting.operational", "mssp.multi_environment"],
            implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
            entitled=CommunityEntitlements().granted_capabilities(),
        )
        self.assertEqual(
            ("reporting.operational", "environment.multi"),
            resolution.requested,
        )
        self.assertEqual(1, resolution.enabled.count("reporting.operational"))
        self.assertNotIn("environment.multi", resolution.enabled)

    def test_requested_names_never_escalate_entitlement(self):
        resolution = self.registry.resolve(
            requested=["validation.openaev", "mssp.multi_tenant"],
            implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
            entitled=CommunityEntitlements().granted_capabilities(),
        )
        self.assertNotIn("validation.openaev", resolution.enabled)
        self.assertNotIn("mssp.multi_tenant", resolution.enabled)
        self.assertTrue(set(resolution.requested).issubset(set(resolution.known)))

    def test_unknown_and_normalization_are_deterministic(self):
        resolution = self.registry.resolve(
            requested=[" UNKNOWN-CAPABILITY ", "unknown_capability", " source.otx ", "source.otx"],
            implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
            entitled=CommunityEntitlements().granted_capabilities(),
        )
        self.assertEqual(("source.otx",), resolution.requested)
        self.assertEqual(("unknown_capability",), resolution.unknown)
        self.assertEqual(tuple(sorted(resolution.known)), resolution.known)

    def test_deferred_names_are_not_canonical(self):
        resolution = self.registry.resolve(
            requested=["source.search", "ingestion.preview"],
            implemented=COMMUNITY_IMPLEMENTED_CAPABILITIES,
            entitled=CommunityEntitlements().granted_capabilities(),
        )
        self.assertEqual((), resolution.requested)
        self.assertEqual(("source.search", "ingestion.preview"), resolution.unknown)

    def test_registry_rejects_invalid_aliases(self):
        with self.assertRaises(ValueError):
            CapabilityRegistry(["one"], {"one": "one"})
        with self.assertRaises(ValueError):
            CapabilityRegistry(["one"], {"two": "missing"})


class CommunityEntitlementsTests(unittest.TestCase):
    def test_provider_is_structural_and_offline(self):
        provider = CommunityEntitlements()
        self.assertIsInstance(provider, EntitlementProvider)
        self.assertEqual(COMMUNITY_ENTITLED_CAPABILITIES, provider.granted_capabilities())
        self.assertNotIn("ui.basic", provider.granted_capabilities())
        self.assertNotIn("environment.multi", provider.granted_capabilities())


if __name__ == "__main__":
    unittest.main()
