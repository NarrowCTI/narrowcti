import os
import unittest
from unittest.mock import patch

from connectors.misp.settings import load_settings


class MISPSettingsTests(unittest.TestCase):
    def test_load_settings_builds_adapter_limits(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
            "MISP_QUERIES": "tlp:green, ransomware",
            "MISP_VERIFY_TLS": "true",
            "MISP_MAX_EVENTS_PER_RUN": "2",
            "MISP_MAX_ATTRIBUTES_PER_EVENT": "500",
            "MISP_OVERSIZED_EVENT_ACTION": "truncate",
            "MISP_STATE_FILE": "/app/state/misp.json",
            "MISP_DECISION_AUDIT_FILE": "/app/state/misp-decisions.jsonl",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(["tlp:green", "ransomware"], settings.misp_queries)
        self.assertTrue(settings.misp_verify_tls)
        self.assertEqual(2, settings.adapter_limits.max_events_per_run)
        self.assertEqual(500, settings.adapter_limits.max_attributes_per_event)
        self.assertEqual("truncate", settings.adapter_limits.oversized_event_action)
        self.assertEqual("/app/state/misp.json", settings.state_file)
        self.assertEqual("/app/state/misp-decisions.jsonl", settings.decision_audit_file)

    def test_load_settings_requires_queries(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
        }

        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "MISP_QUERIES"):
                load_settings()

    def test_load_settings_rejects_invalid_oversized_action(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
            "MISP_QUERIES": "tlp:green",
            "MISP_OVERSIZED_EVENT_ACTION": "import",
        }

        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "oversized_event_action"):
                load_settings()


if __name__ == "__main__":
    unittest.main()