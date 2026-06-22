import contextlib
import io
import json
import os
import tempfile
import unittest

from gateway.mitre import main
from tests.test_mitre_attack import sample_attack_bundle


class GatewayMITRETests(unittest.TestCase):
    def test_build_cache_command_writes_normalized_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle_file = os.path.join(directory, "enterprise-attack.json")
            cache_file = os.path.join(directory, "mitre_attack_cache.json")
            with open(bundle_file, "w", encoding="utf-8") as handle:
                json.dump(sample_attack_bundle(), handle)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "build-cache",
                        "--bundle",
                        bundle_file,
                        "--cache-file",
                        cache_file,
                    ]
                )

            with open(cache_file, "r", encoding="utf-8") as handle:
                cache = json.load(handle)

        self.assertEqual(0, result)
        self.assertEqual(2, cache["technique_count"])
        self.assertEqual(2, json.loads(output.getvalue())["technique_count"])

    def test_resolve_command_reads_cache_and_prints_results(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle_file = os.path.join(directory, "enterprise-attack.json")
            cache_file = os.path.join(directory, "mitre_attack_cache.json")
            with open(bundle_file, "w", encoding="utf-8") as handle:
                json.dump(sample_attack_bundle(), handle)
            with contextlib.redirect_stdout(io.StringIO()):
                main(
                    [
                        "build-cache",
                        "--bundle",
                        bundle_file,
                        "--cache-file",
                        cache_file,
                    ]
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["resolve", "--cache-file", cache_file, "T1059"])

        resolved = json.loads(output.getvalue())
        self.assertEqual(0, result)
        self.assertEqual("T1059", resolved[0]["attack_id"])
        self.assertEqual("Command and Scripting Interpreter", resolved[0]["name"])


if __name__ == "__main__":
    unittest.main()
