"""Build-time projection of canonical brand assets into the runtime package."""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPyWithBrandAssets(build_py):
    def run(self):
        super().run()
        repository_root = Path(__file__).resolve().parent
        brand_source = repository_root / "docs" / "assets" / "brand"
        brand_target = (
            Path(self.build_lib)
            / "narrowcti"
            / "api"
            / "web"
            / "static"
            / "brand"
        )
        if not brand_source.is_dir():
            raise RuntimeError("canonical docs/assets/brand directory is missing")
        shutil.copytree(brand_source, brand_target, dirs_exist_ok=True)


setup(cmdclass={"build_py": BuildPyWithBrandAssets})
