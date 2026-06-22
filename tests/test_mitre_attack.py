import json
import os
import tempfile
import unittest

from core.mitre_attack import (
    MITREAttackResolver,
    build_attack_cache,
    load_attack_cache,
    normalize_attack_id,
    refresh_attack_cache,
    save_attack_cache,
)


def sample_attack_bundle():
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1059",
                "name": "Command and Scripting Interpreter",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1059-001",
                "name": "PowerShell",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution",
                    }
                ],
            },
            {
                "type": "malware",
                "id": "malware--ignored",
                "name": "Ignored",
            },
        ],
    }


class MITREAttackTests(unittest.TestCase):
    def test_build_attack_cache_extracts_techniques_and_tactics(self):
        cache = build_attack_cache(sample_attack_bundle())

        self.assertEqual("mitre-attack", cache["source"])
        self.assertEqual(2, cache["technique_count"])
        self.assertEqual(
            "Command and Scripting Interpreter",
            cache["techniques"]["T1059"]["name"],
        )
        self.assertEqual(["execution"], cache["techniques"]["T1059"]["tactics"])
        self.assertEqual(
            "https://attack.mitre.org/techniques/T1059/",
            cache["techniques"]["T1059"]["url"],
        )

    def test_resolver_returns_known_and_missing_techniques_in_input_order(self):
        resolver = MITREAttackResolver(cache=build_attack_cache(sample_attack_bundle()))

        resolved = resolver.resolve(["t1059", "T9999", "T1059.001"])

        self.assertEqual("T1059", resolved[0]["attack_id"])
        self.assertTrue(resolved[0]["found"])
        self.assertEqual("Command and Scripting Interpreter", resolved[0]["name"])
        self.assertEqual(["execution"], resolved[0]["tactics"])
        self.assertEqual("T9999", resolved[1]["attack_id"])
        self.assertFalse(resolved[1]["found"])
        self.assertEqual("T1059.001", resolved[2]["attack_id"])
        self.assertEqual("PowerShell", resolved[2]["name"])

    def test_load_attack_cache_accepts_raw_stix_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_file = os.path.join(directory, "enterprise-attack.json")
            with open(cache_file, "w", encoding="utf-8") as handle:
                json.dump(sample_attack_bundle(), handle)

            cache = load_attack_cache(cache_file)

        self.assertEqual(2, cache["technique_count"])
        self.assertIn("T1059", cache["techniques"])

    def test_save_attack_cache_writes_normalized_cache(self):
        cache = build_attack_cache(sample_attack_bundle())
        with tempfile.TemporaryDirectory() as directory:
            cache_file = os.path.join(directory, "mitre_attack_cache.json")
            save_attack_cache(cache, cache_file)
            with open(cache_file, "r", encoding="utf-8") as handle:
                saved = json.load(handle)

        self.assertEqual(2, saved["technique_count"])
        self.assertEqual("PowerShell", saved["techniques"]["T1059.001"]["name"])

    def test_refresh_attack_cache_uses_explicit_url_and_opener(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps(sample_attack_bundle()).encode("utf-8")

        calls = []

        def opener(url, timeout):
            calls.append((url, timeout))
            return Response()

        with tempfile.TemporaryDirectory() as directory:
            cache_file = os.path.join(directory, "mitre_attack_cache.json")
            cache = refresh_attack_cache(
                cache_file,
                stix_url="https://example.com/enterprise.json",
                timeout=10,
                opener=opener,
            )

        self.assertEqual([("https://example.com/enterprise.json", 10)], calls)
        self.assertEqual(2, cache["technique_count"])

    def test_normalize_attack_id_accepts_technique_and_subtechnique_only(self):
        self.assertEqual("T1059", normalize_attack_id("t1059"))
        self.assertEqual("T1059.001", normalize_attack_id("T1059.001"))
        self.assertEqual("", normalize_attack_id("uses T1059"))


if __name__ == "__main__":
    unittest.main()
