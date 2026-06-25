import unittest

from core.feed_contract import FeedSource
from core.source_identity import feed_source_identity_name, source_identity_name


class SourceIdentityTests(unittest.TestCase):
    def test_source_identity_uses_canonical_otx_name(self):
        self.assertEqual(
            "OTX AlienVault",
            source_identity_name(source_key="alienvault:otx"),
        )

    def test_feed_source_identity_uses_canonical_misp_name(self):
        source = FeedSource(name="MISP", source_type="external_import", provider="MISP")

        self.assertEqual("MISP", feed_source_identity_name(source))

    def test_source_identity_falls_back_to_provider_and_name(self):
        self.assertEqual(
            "ExampleFeed Vendor",
            source_identity_name(source_name="ExampleFeed", provider="Vendor"),
        )


if __name__ == "__main__":
    unittest.main()
