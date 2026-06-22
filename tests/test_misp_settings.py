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
            "MISP_MAX_IOCS_PER_EVENT": "250",
            "MISP_OVERSIZED_EVENT_ACTION": "truncate",
            "MISP_RUN_ONCE": "true",
            "MISP_FROM_DATE": "2026-01-01",
            "MISP_TO_DATE": "2026-01-31",
            "MISP_TAGS": "tlp:green, type:OSINT",
            "MISP_PUBLISHED_ONLY": "true",
            "MISP_SOURCE_CONFIDENCE": "65",
            "INGEST_PAUSE_SECONDS": "5",
            "MIN_SCORE_TO_INGEST": "70",
            "MIN_SCORE_FOR_OLD_EVENT": "85",
            "ENABLE_QUARANTINE": "false",
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
        self.assertEqual(250, settings.max_iocs_per_event)
        self.assertTrue(settings.run_once)
        self.assertEqual(
            {
                "from": "2026-01-01",
                "to": "2026-01-31",
                "tags": ["tlp:green", "type:OSINT"],
                "published": True,
            },
            settings.search_filters,
        )
        self.assertEqual(5, settings.ingest_pause_seconds)
        self.assertEqual(65, settings.source_confidence)
        self.assertEqual(70, settings.min_score_to_ingest)
        self.assertEqual(85, settings.min_score_for_old_event)
        self.assertFalse(settings.enable_quarantine)
        self.assertEqual("/app/state/misp.json", settings.state_file)
        self.assertEqual("/app/state/misp-decisions.jsonl", settings.decision_audit_file)

    def test_load_settings_defaults_to_dry_run(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
            "MISP_QUERIES": "tlp:green",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertTrue(settings.dry_run)

    def test_load_settings_accepts_gateway_policy_fallbacks(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
            "MISP_QUERIES": "tlp:green",
            "NARROWCTI_MIN_SCORE_TO_INGEST": "75",
            "NARROWCTI_MAX_DAYS_OLD": "365",
            "NARROWCTI_ENABLE_QUARANTINE": "false",
            "NARROWCTI_QUARANTINE_SCORE_THRESHOLD": "55",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(75, settings.min_score_to_ingest)
        self.assertEqual(365, settings.max_days_old)
        self.assertFalse(settings.enable_quarantine)
        self.assertEqual(55, settings.quarantine_score_threshold)

    def test_load_settings_legacy_policy_names_override_gateway_defaults(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
            "MISP_QUERIES": "tlp:green",
            "NARROWCTI_MIN_SCORE_TO_INGEST": "75",
            "NARROWCTI_ENABLE_QUARANTINE": "false",
            "MIN_SCORE_TO_INGEST": "65",
            "ENABLE_QUARANTINE": "true",
        }

        with patch.dict(os.environ, env, clear=True):
            settings = load_settings()

        self.assertEqual(65, settings.min_score_to_ingest)
        self.assertTrue(settings.enable_quarantine)

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

    def test_load_settings_rejects_invalid_max_iocs(self):
        env = {
            "OPENCTI_URL": "http://opencti:8080",
            "OPENCTI_TOKEN": "token",
            "MISP_URL": "http://misp.local",
            "MISP_KEY": "misp-key",
            "MISP_QUERIES": "tlp:green",
            "MISP_MAX_IOCS_PER_EVENT": "0",
        }

        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "max_iocs_per_event"):
                load_settings()


if __name__ == "__main__":
    unittest.main()
