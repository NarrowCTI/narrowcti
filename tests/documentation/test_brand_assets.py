from __future__ import annotations

import hashlib
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BRAND = ROOT / "docs/assets/brand"
EXPECTED = {
    "logo/narrowcti-logo-horizontal-dark.svg": "a750e4a6b1a48f80552bafce3086fee5ed8e4ab88ebed309cff656ddfa108699",
    "logo/narrowcti-logo-horizontal-light.svg": "604eb94e86a30f0e68d62c62f9ca05761269b0cf2cabd47fe73809d6baaf7355",
    "logo/narrowcti-logo-vertical-dark.svg": "c4ddfd13c747bdfa26ffe7f88a831f124cc7f5cab71546bba15b52fa91e318b5",
    "logo/narrowcti-logo-vertical-light.svg": "e8cba68b559622417fd330d24ce0da611288286b43b4cd17c301749bab34cb6b",
    "symbol/narrowcti-symbol-gradient.svg": "72484c7381f1fe63a5e161315a00a1a620ff4ef67f04ae56fc705259d4700420",
    "symbol/narrowcti-symbol-black.svg": "e088eeeedc62d46e2daf86b7100d10aeec29876fd682afef89ee3d70e4c931da",
    "symbol/narrowcti-symbol-white.svg": "69402c0fa7e14a328f399f0c151a605a5bc4f5b8b8dedf21cdbddf04f29662de",
    "banners/narrowcti-readme-banner-2172x724.png": "d74a8278c2c69f73bfd2fef26cd7a8484e5df62f2b66bed769c8782f40286a55",
    "favicon/narrowcti-favicon.ico": "628089c5423a12426e0fec68a3d9961f192cafb49836d6fa7e4d0c7123322a11",
}


class BrandAssetTests(unittest.TestCase):
    def test_canonical_tree_is_exact_and_byte_stable(self):
        actual = {p.relative_to(BRAND).as_posix() for p in BRAND.rglob("*") if p.is_file()}
        self.assertEqual(set(EXPECTED), actual)
        for relative, expected in EXPECTED.items():
            digest = hashlib.sha256((BRAND / relative).read_bytes()).hexdigest()
            self.assertEqual(expected, digest, relative)

    def test_svg_assets_are_safe_rendering_documents(self):
        for relative in EXPECTED:
            if not relative.endswith(".svg"):
                continue
            root = ET.fromstring((BRAND / relative).read_bytes())
            self.assertTrue(root.tag.endswith("svg"), relative)
            for element in root.iter():
                self.assertFalse(element.tag.lower().endswith("script"), relative)
                self.assertFalse(element.tag.lower().endswith("text"), relative)
                self.assertFalse(any(name.lower().startswith("on") for name in element.attrib), relative)
                self.assertFalse(any("href" in name.lower() for name in element.attrib), relative)

    def test_readme_uses_canonical_banner_and_identity(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/assets/brand/banners/narrowcti-readme-banner-2172x724.png", readme)
        self.assertNotIn("NarrowCTI 2.0", readme)


if __name__ == "__main__":
    unittest.main()
