import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pr22_wheel_validator", ROOT / "scripts" / "validate_package_wheel.py"
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class WheelInventoryTests(unittest.TestCase):
    def test_arbitrary_canonical_source_module_is_required_by_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "src" / "narrowcti" / "domain" / "arbitrary.py"
            module.parent.mkdir(parents=True)
            module.write_text("VALUE = 1\n", encoding="utf-8")

            expected = VALIDATOR.expected_runtime_modules(root)
            self.assertIn("narrowcti/domain/arbitrary.py", expected)

            actual = set(expected)
            actual.remove("narrowcti/domain/arbitrary.py")
            with self.assertRaisesRegex(AssertionError, "arbitrary.py"):
                VALIDATOR.assert_runtime_inventory(actual, root)

    def test_removed_nested_facades_are_excluded_from_source_expectation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            removed = root / "src" / "narrowcti" / "core" / "legacy.py"
            removed.parent.mkdir(parents=True)
            removed.write_text("VALUE = 1\n", encoding="utf-8")
            self.assertNotIn("narrowcti/core/legacy.py", VALIDATOR.expected_runtime_modules(root))


if __name__ == "__main__":
    unittest.main()
