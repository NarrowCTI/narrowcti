import json
import unittest

from core.runtime_config import (
    OpenCTIConfig,
    load_runtime_config,
    parse_misp_verify_tls,
)


class RuntimeConfigTests(unittest.TestCase):
    def test_core_resolves_from_mapping_without_process_environment(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "canary-opencti-token",
            "MISP_URL": "https://misp.example",
            "MISP_KEY": "canary-misp-key",
            "OTX_API_KEY": "canary-otx-key",
            "MISP_VERIFY_TLS": "yes",
        }

        config = load_runtime_config(env, enabled_sources=("misp", "otx"))

        self.assertEqual("https://misp.example", config.misp.url)
        self.assertTrue(config.misp_verify_tls)
        safe = config.to_safe_dict()
        self.assertNotIn("canary-opencti-token", json.dumps(safe))
        self.assertNotIn("canary-misp-key", json.dumps(safe))
        self.assertNotIn("canary-otx-key", json.dumps(safe))
        self.assertNotIn("canary-opencti-token", repr(config))

    def test_inactive_sources_do_not_require_credentials(self):
        config = load_runtime_config(
            {"MISP_VERIFY_TLS": "not-a-boolean"}, enabled_sources=()
        )

        self.assertIsNone(config.opencti)
        self.assertIsNone(config.misp)
        self.assertIsNone(config.otx)
        self.assertTrue(config.misp_verify_tls)

    def test_active_source_requires_only_its_credentials(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "OTX_API_KEY": "otx-key",
        }

        config = load_runtime_config(env, enabled_sources=("otx",))

        self.assertIsNotNone(config.otx)
        self.assertIsNone(config.misp)

    def test_opencti_safe_representation_is_structural(self):
        config = OpenCTIConfig("http://opencti:8080", "canary-opencti-token")

        self.assertNotIn("canary-opencti-token", repr(config))
        self.assertEqual(
            {"url": "http://opencti:8080", "configured": True},
            config.to_safe_dict(),
        )

    def test_misp_tls_parser_is_fail_closed(self):
        self.assertTrue(parse_misp_verify_tls(None))
        self.assertFalse(parse_misp_verify_tls("0"))
        with self.assertRaises(ValueError):
            parse_misp_verify_tls("enabled")


if __name__ == "__main__":
    unittest.main()
