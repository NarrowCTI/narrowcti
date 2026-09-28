"""Legacy Review API environment names remain Web fallbacks."""

from __future__ import annotations

import unittest

from narrowcti.infrastructure.config.web_settings import load_web_settings


class WebSettingsCompatibilityTests(unittest.TestCase):
    def test_legacy_host_and_body_limit_are_fallbacks(self):
        settings = load_web_settings({
            "NARROWCTI_REVIEW_API_ALLOWED_HOSTS": "legacy.example,localhost",
            "NARROWCTI_REVIEW_API_MAX_BODY_BYTES": "32768",
        })
        self.assertEqual(("legacy.example", "localhost"), settings.allowed_hosts)
        self.assertEqual(32768, settings.max_request_body_bytes)

    def test_web_names_take_precedence_over_legacy_fallbacks(self):
        settings = load_web_settings({
            "NARROWCTI_REVIEW_API_ALLOWED_HOSTS": "legacy.example",
            "NARROWCTI_WEB_ALLOWED_HOSTS": "web.example",
            "NARROWCTI_REVIEW_API_MAX_BODY_BYTES": "32768",
            "NARROWCTI_WEB_MAX_BODY_BYTES": "65536",
        })
        self.assertEqual(("web.example",), settings.allowed_hosts)
        self.assertEqual(65536, settings.max_request_body_bytes)


if __name__ == "__main__":
    unittest.main()
