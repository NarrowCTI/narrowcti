"""Settings boundary for the independently configured Community Web role."""

from __future__ import annotations

import unittest

from narrowcti.infrastructure.config.web_settings import load_web_settings


class WebSettingsTests(unittest.TestCase):
    def test_explorer_uses_only_web_namespaces_and_defaults_tls_to_strict(self):
        settings = load_web_settings(
            {
                "MISP_URL": "http://legacy-misp",
                "MISP_KEY": "legacy-misp-secret",
                "MISP_VERIFY_TLS": "false",
                "OTX_API_KEY": "legacy-otx-secret",
            }
        )
        self.assertEqual(settings.sources.misp_url, "")
        self.assertTrue(settings.sources.misp_verify_tls)
        self.assertFalse(hasattr(settings.sources, "misp_key"))
        self.assertFalse(hasattr(settings.sources, "otx_api_key"))
        self.assertNotIn("legacy-misp-secret", repr(settings))
        self.assertNotIn("legacy-otx-secret", repr(settings))

    def test_web_tls_setting_is_strict_and_invalid_values_fail_closed(self):
        for value in ("true", "1", "yes"):
            self.assertTrue(load_web_settings({"NARROWCTI_WEB_MISP_VERIFY_TLS": value}).sources.misp_verify_tls)
        for value in ("false", "0", "no"):
            self.assertFalse(load_web_settings({"NARROWCTI_WEB_MISP_VERIFY_TLS": value}).sources.misp_verify_tls)
        with self.assertRaisesRegex(ValueError, "NARROWCTI_WEB_MISP_VERIFY_TLS"):
            load_web_settings({"NARROWCTI_WEB_MISP_VERIFY_TLS": "typo"})

    def test_public_origin_is_origin_only_and_remote_http_is_rejected(self):
        settings = load_web_settings({"NARROWCTI_WEB_PUBLIC_ORIGIN": "https://cti.example/"})
        self.assertEqual(settings.public_origin, "https://cti.example")
        with self.assertRaises(ValueError):
            load_web_settings({"NARROWCTI_WEB_PUBLIC_ORIGIN": "https://cti.example/web"})
        with self.assertRaises(ValueError):
            load_web_settings({"NARROWCTI_WEB_PUBLIC_ORIGIN": "http://cti.example"})

    def test_unconfigured_source_credentials_do_not_prevent_web_startup(self):
        settings = load_web_settings({"NARROWCTI_REVIEW_API_CREDENTIALS_FILE": "synthetic-file"})
        self.assertEqual(settings.port, 8081)
        self.assertEqual(settings.sources.otx_key_file, "")


if __name__ == "__main__":
    unittest.main()
