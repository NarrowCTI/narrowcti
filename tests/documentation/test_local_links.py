from __future__ import annotations

import unittest
from pathlib import Path

from scripts.check_documentation_links import check_paths, extract_targets


ROOT = Path(__file__).resolve().parents[2]


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
