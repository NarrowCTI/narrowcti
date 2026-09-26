"""Validate the installed NarrowCTI distribution without a source checkout."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import os
import subprocess
import sys
import tempfile
from pathlib import Path


PACKAGE_ROOTS = ("narrowcti", "connectors", "core", "exporters", "gateway")
PUBLIC_IMPORTS = (
    "narrowcti",
    "gateway.connector",
    "gateway.preflight",
    "core.feed_contract",
    "connectors.misp.feed_adapter",
    "exporters.stix_builder",
)


def _distribution_files() -> tuple[Path, ...]:
    distribution = importlib.metadata.distribution("narrowcti")
    files = distribution.files or ()
    selected = []
    for relative in files:
        path = Path(relative)
        if path.suffix != ".py":
            continue
        if path.parts and path.parts[0] in PACKAGE_ROOTS:
            selected.append(distribution.locate_file(relative).resolve())
    if not selected:
        raise RuntimeError("the installed narrowcti distribution contains no runtime Python files")
    return tuple(sorted(set(selected)))


def _assert_not_checkout(paths: tuple[Path, ...]) -> None:
    checkout = Path.cwd().resolve()
    for path in paths:
        try:
            path.relative_to(checkout)
        except ValueError:
            continue
        raise AssertionError(f"installed runtime file resolves inside the checkout: {path}")


def _compile(paths: tuple[Path, ...]) -> None:
    with tempfile.TemporaryDirectory(prefix="narrowcti-pyc-") as cache:
        env = os.environ.copy()
        env["PYTHONPYCACHEPREFIX"] = cache
        for path in paths:
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(path)],
                env=env,
                cwd=cache,
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode:
                raise RuntimeError(result.stderr or f"could not compile {path}")


def _check_imports() -> None:
    child_env = os.environ.copy()
    child_env.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory(prefix="narrowcti-runtime-") as cwd:
        code = """
import importlib
import importlib.metadata
import importlib.util
import os
import sys

expected = {imports!r}
for name in expected:
    module = importlib.import_module(name)
    location = getattr(module, "__file__", None)
    if not location:
        raise AssertionError(f"{{name}} has no installed file")
    if os.path.abspath(location).startswith(os.path.abspath({checkout!r})):
        raise AssertionError(f"{{name}} resolved from checkout: {{location}}")

for name in {roots!r}:
    module = importlib.import_module(name)
    location = getattr(module, "__file__", None)
    if not location:
        raise AssertionError(f"{{name}} has no package file")
    if os.path.abspath(location).startswith(os.path.abspath({checkout!r})):
        raise AssertionError(f"{{name}} resolved from checkout: {{location}}")

assert importlib.metadata.version("narrowcti")
assert not os.environ.get("PYTHONPATH")
assert "/app/src" not in sys.path
print("installed-package-imports-ok")
""".format(
            imports=PUBLIC_IMPORTS,
            roots=PACKAGE_ROOTS,
            checkout=str(Path.cwd().resolve()),
        )
        subprocess.run(
            [sys.executable, "-c", code],
            cwd=cwd,
            env=child_env,
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compile", action="store_true")
    parser.add_argument("--imports", action="store_true")
    args = parser.parse_args()
    paths = _distribution_files()
    _assert_not_checkout(paths)
    if args.compile:
        _compile(paths)
    if args.imports:
        _check_imports()
    if not args.compile and not args.imports:
        parser.error("at least one of --compile or --imports is required")
    print(f"runtime-package-validation-ok files={len(paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
