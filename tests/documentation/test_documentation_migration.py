from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/development/documentation-migration-map.json"
DISPOSITIONS = {"STAY", "MOVE", "LEGACY-RETAIN", "CANONICAL-REPLACEMENT"}


def _git_index_bytes(path: Path) -> bytes:
    """Read the exact tracked blob bytes from the current Git index."""

    return subprocess.check_output(
        ["git", "show", f":{path.relative_to(ROOT).as_posix()}"],
        cwd=ROOT,
    )


class DocumentationMigrationTests(unittest.TestCase):
    def test_baseline_docs_have_one_explicit_disposition(self):
        payload = json.loads(LEDGER.read_text(encoding="utf-8"))
        entries = payload["entries"]
        old_paths = [entry["old_path"] for entry in entries]
        self.assertEqual(len(old_paths), len(set(old_paths)))
        self.assertEqual(payload["baseline_docs_count"], len(old_paths))
        path_digest = hashlib.sha256("\n".join(sorted(old_paths)).encode()).hexdigest()
        self.assertEqual(payload["baseline_paths_sha256"], path_digest)
        self.assertTrue(all(entry["disposition"] in DISPOSITIONS for entry in entries))

        move_targets = [entry["new_path"] for entry in entries if entry["disposition"] == "MOVE"]
        self.assertEqual(len(move_targets), len(set(move_targets)))
        for entry in entries:
            target = ROOT / entry["new_path"]
            self.assertTrue(target.exists(), entry["new_path"])
            if entry["disposition"] in {"MOVE", "CANONICAL-REPLACEMENT"}:
                self.assertTrue(target.exists(), entry["new_path"])
            if entry["immutable"] and entry.get("sha256_before"):
                digest = hashlib.sha256(_git_index_bytes(target)).hexdigest()
                self.assertEqual(entry["sha256_before"], digest, entry["old_path"])

    def test_current_docs_do_not_reference_moved_paths(self):
        payload = json.loads(LEDGER.read_text(encoding="utf-8"))
        forbidden = {
            entry["old_path"]
            for entry in payload["entries"]
            if entry["disposition"] == "MOVE"
        }
        files = {
            ROOT / name
            for name in ("README.md", "CONTRIBUTING.md", "SUPPORT.md", "SECURITY.md")
        }
        files.update(
            ROOT / entry["new_path"]
            for entry in payload["entries"]
            if not entry["historical"] and entry["new_path"].endswith(".md")
        )
        violations = []
        for path in sorted(files):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for old_path in sorted(forbidden):
                if old_path in text:
                    violations.append(f"{path.relative_to(ROOT)} references {old_path}")
        self.assertEqual([], violations, "\n".join(violations))

    def test_map_does_not_claim_w0_inventory_as_ledger(self):
        payload = json.loads(LEDGER.read_text(encoding="utf-8"))
        self.assertEqual("PR-20 merge baseline", payload["baseline_ref"])
        self.assertEqual(93, payload["baseline_docs_count"])


if __name__ == "__main__":
    unittest.main()
