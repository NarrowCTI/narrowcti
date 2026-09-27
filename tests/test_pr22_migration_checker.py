import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pr22_migration_checker", ROOT / "scripts" / "check_2_0_migration.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
scan = CHECKER.scan


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
                [sys.executable, str(ROOT / "scripts" / "check_2_0_migration.py"), str(root), "--strict"],
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
                [sys.executable, str(ROOT / "scripts" / "check_2_0_migration.py"), str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)

    def test_all_multi_import_aliases_are_scanned(self):
        temp, root = self._tree(
            {
                "consumer.py": (
                    "import os, narrowcti.core.feed_contract\n"
                    "import narrowcti.core.feed_contract, os\n"
                )
            }
        )
        with temp:
            findings = scan(root)
            self.assertEqual(2, len(findings))
            self.assertTrue(all(finding.severity == "error" for finding in findings))

    def test_removed_prefix_matching_uses_module_boundaries(self):
        temp, root = self._tree({"consumer.py": "import narrowcti.coretools\n"})
        with temp:
            self.assertEqual((), scan(root))

    def test_from_narrowcti_legacy_namespace_is_error(self):
        temp, root = self._tree({"consumer.py": "from narrowcti import core\n"})
        with temp:
            findings = scan(root)
            self.assertEqual(1, len(findings))
            self.assertEqual("error", findings[0].severity)

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
