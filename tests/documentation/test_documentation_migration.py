from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/development/documentation-migration-map.json"
DISPOSITIONS = {"STAY", "MOVE", "LEGACY-RETAIN", "CANONICAL-REPLACEMENT"}


class DocumentationMigrationTests(unittest.TestCase):
    def test_baseline_docs_have_one_explicit_disposition(self):
        payload = json.loads(LEDGER.read_text(encoding="utf-8"))
        baseline = set(
            subprocess.check_output(
                ["git", "ls-tree", "-r", "--name-only", payload["baseline_commit"], "docs"],
                cwd=ROOT,
                text=True,
            ).splitlines()
        )
        entries = payload["entries"]
        old_paths = [entry["old_path"] for entry in entries]
        self.assertEqual(len(old_paths), len(set(old_paths)))
        self.assertEqual(baseline, set(old_paths))
        self.assertTrue(all(entry["disposition"] in DISPOSITIONS for entry in entries))

        move_targets = [entry["new_path"] for entry in entries if entry["disposition"] == "MOVE"]
        self.assertEqual(len(move_targets), len(set(move_targets)))
        for entry in entries:
            target = ROOT / entry["new_path"]
            if entry["disposition"] in {"MOVE", "CANONICAL-REPLACEMENT"}:
                self.assertTrue(target.exists(), entry["new_path"])
            if entry["disposition"] == "MOVE" and entry["historical"] and entry["immutable"]:
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
                self.assertEqual(entry["sha256_before"], digest, entry["old_path"])

    def test_map_does_not_claim_w0_inventory_as_ledger(self):
        payload = json.loads(LEDGER.read_text(encoding="utf-8"))
        self.assertNotEqual(payload["baseline_ref"], "w0-inventory")
        self.assertEqual(93, len(payload["entries"]))


if __name__ == "__main__":
    unittest.main()
