"""Read-only Community 2.0 migration checker.

The checker reports legacy imports without rewriting them.  Legacy top-level
roots remain supported compatibility surfaces; nested ``narrowcti.<root>``
facades are removed and therefore reported as errors.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path


LEGACY_ROOTS = ("core", "connectors", "exporters", "gateway")
REMOVED_PREFIXES = tuple(f"narrowcti.{root}" for root in LEGACY_ROOTS)
EXCLUDED_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "state", "build", "dist"}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    severity: str
    message: str


def _module_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
        return names[0] if names else None
    if isinstance(node, ast.ImportFrom):
        if node.level:
            return None
        return node.module
    return None


def iter_python_files(root: Path):
    for path in root.rglob("*.py"):
        if EXCLUDED_PARTS.intersection(path.parts):
            continue
        yield path


def scan(root: Path) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for path in iter_python_files(root):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            findings.append(Finding(path, getattr(exc, "lineno", 1) or 1, "error", f"cannot read/parse: {exc}"))
            continue
        for node in ast.walk(tree):
            module = _module_name(node)
            if not module:
                continue
            if module == "narrowcti.compat" or module.startswith(REMOVED_PREFIXES):
                findings.append(Finding(path, node.lineno, "error", f"removed transitional path: {module}"))
            elif module.split(".", 1)[0] in LEGACY_ROOTS:
                findings.append(
                    Finding(
                        path,
                        node.lineno,
                        "warning",
                        f"legacy compatibility import: {module}; manual migration required",
                    )
                )
    return tuple(findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--strict", action="store_true", help="return 2 when warnings are present")
    args = parser.parse_args(argv)
    findings = scan(args.root.resolve())
    for finding in findings:
        relative = finding.path.relative_to(args.root.resolve())
        print(f"{finding.severity}: {relative}:{finding.line}: {finding.message}")
    if any(finding.severity == "error" for finding in findings):
        return 1
    if args.strict and findings:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
