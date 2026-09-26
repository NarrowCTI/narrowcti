from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check_documentation_links.py"
_SPEC = importlib.util.spec_from_file_location("documentation_link_checker", CHECKER)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
check_paths = _MODULE.check_paths
extract_targets = _MODULE.extract_targets


class DocumentationLinkTests(unittest.TestCase):
    def test_local_documentation_links_are_valid(self):
        self.assertEqual([], check_paths(ROOT))

    def test_code_spans_and_fences_are_not_links(self):
        text = """
`[inline](missing-inline.md)`

```markdown
[fenced](missing-fenced.md)
```

[real](docs/README.md)
"""
        self.assertEqual([("docs/README.md", 8)], extract_targets(text))


if __name__ == "__main__":
    unittest.main()
