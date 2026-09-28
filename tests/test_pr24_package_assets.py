"""Build projection contract for canonical Web brand assets."""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "narrowcti_wheel_validator", ROOT / "scripts" / "validate_package_wheel.py"
)
if VALIDATOR_SPEC is None or VALIDATOR_SPEC.loader is None:
    raise RuntimeError("could not load the wheel validator")
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)
assert_brand_asset_projection = VALIDATOR.assert_brand_asset_projection


class BrandAssetProjectionTests(unittest.TestCase):
    def test_every_canonical_asset_must_be_projected_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "docs" / "assets" / "brand"
            (source / "logo").mkdir(parents=True)
            (source / "favicon").mkdir(parents=True)
            (source / "logo" / "logo.svg").write_bytes(b"<svg/>\n")
            (source / "favicon" / "icon.ico").write_bytes(b"icon-bytes")
            wheel = root / "synthetic.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for asset in source.rglob("*"):
                    if asset.is_file():
                        relative = asset.relative_to(source).as_posix()
                        archive.writestr(
                            f"narrowcti/api/web/static/brand/{relative}",
                            asset.read_bytes(),
                        )
            with zipfile.ZipFile(wheel) as archive:
                assert_brand_asset_projection(archive, root)

            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(
                    "narrowcti/api/web/static/brand/logo/logo.svg",
                    b"<svg/>\n",
                )
            with zipfile.ZipFile(wheel) as archive:
                with self.assertRaisesRegex(AssertionError, "favicon/icon.ico"):
                    assert_brand_asset_projection(archive, root)


class HtmxAssetProvenanceTests(unittest.TestCase):
    def test_vendored_htmx_version_checksum_license_and_notice_are_consistent(self):
        static = ROOT / "src" / "narrowcti" / "api" / "web" / "static"
        asset = static / "htmx.min.js"
        version = (static / "HTMX-VERSION.txt").read_text(encoding="utf-8")
        license_text = (static / "HTMX-LICENSE.txt").read_text(encoding="utf-8")
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")

        self.assertIn("htmx 2.0.11", version)
        self.assertIn("SHA-256: " + hashlib.sha256(asset.read_bytes()).hexdigest(), version)
        self.assertIn("Zero-Clause BSD (0BSD)", license_text)
        self.assertIn("htmx 2.0.11", notices)
        self.assertIn("Zero-Clause BSD (0BSD)", notices)


if __name__ == "__main__":
    unittest.main()
