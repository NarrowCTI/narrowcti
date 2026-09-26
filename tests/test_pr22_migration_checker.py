import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.check_2_0_migration import scan


class MigrationCheckerTests(unittest.TestCase):
    def _tree(self, files):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return temp, root

    def test_canonical_tree_is_clean(self):
        temp, root = self._tree({"src/narrowcti/domain/example.py": "from .value import Value\n"})
        with temp:
            self.assertEqual((), scan(root))

    def test_legacy_import_is_warning_and_strict_exit_two(self):
        temp, root = self._tree({"consumer.py": "from core.scoring import calculate_score\n"})
        with temp:
            findings = scan(root)
            self.assertEqual(1, len(findings))
            self.assertEqual("warning", findings[0].severity)
            result = subprocess.run(
                [sys.executable, "scripts/check_2_0_migration.py", str(root), "--strict"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("manual migration required", result.stdout)

    def test_removed_nested_facade_is_error(self):
        temp, root = self._tree({"consumer.py": "import narrowcti.core.feed_contract\n"})
        with temp:
            findings = scan(root)
            self.assertEqual("error", findings[0].severity)
            result = subprocess.run(
                [sys.executable, "scripts/check_2_0_migration.py", str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)

    def test_exclusions_are_not_scanned(self):
        temp, root = self._tree(
            {
                ".venv/ignored.py": "import narrowcti.core.feed_contract\n",
                "state/ignored.py": "import core.scoring\n",
                "__pycache__/ignored.py": "import gateway.connector\n",
            }
        )
        with temp:
            self.assertEqual((), scan(root))

    def test_syntax_error_is_checker_error(self):
        temp, root = self._tree({"broken.py": "def broken(:\n"})
        with temp:
            findings = scan(root)
            self.assertEqual("error", findings[0].severity)


if __name__ == "__main__":
    unittest.main()
