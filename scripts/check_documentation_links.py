"""Check local Markdown and HTML documentation links without network access."""

from __future__ import annotations

import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit


_FENCE_RE = re.compile(r"(?ms)(^\s*(```|~~~).*$\n.*?^\s*\2\s*$)")
_INLINE_RE = re.compile(r"`[^`\n]*`")
_MD_LINK_RE = re.compile(r"!?(?:\[[^\]]*\])\((?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)")
_HISTORICAL_LINK_EXCEPTIONS = {
    ("docs/validation/w0-baseline-v1.1.1.md", "release-v1.1.1.md"): "docs/releases/release-v1.1.1.md",
    ("docs/validation/w0-config-baseline-v1.1.1.md", "configuration-reference.md"): "docs/product/configuration-reference.md",
    ("docs/validation/w0-config-baseline-v1.1.1.md", "environment-profiles.md"): "docs/product/environment-profiles.md",
}


class _HTMLLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.targets: list[tuple[str, int]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() in {"href", "src"} and value:
                self.targets.append((value, self.getpos()[0]))


def mask_code(text: str) -> str:
    """Replace fenced blocks and inline code with whitespace, preserving lines."""

    def spaces(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    text = _FENCE_RE.sub(spaces, text)
    return _INLINE_RE.sub(spaces, text)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def extract_targets(text: str) -> list[tuple[str, int]]:
    masked = mask_code(text)
    targets = []
    for match in _MD_LINK_RE.finditer(masked):
        targets.append((match.group(1) or match.group(2), _line_number(text, match.start())))
    parser = _HTMLLinks()
    parser.feed(masked)
    targets.extend(parser.targets)
    return targets


def _is_external(target: str) -> bool:
    parsed = urlsplit(target)
    return bool(parsed.scheme and parsed.scheme.lower() in {"http", "https", "mailto", "data"})


def _case_sensitive_path(root: Path, candidate: Path) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            return False
        if not current.is_dir() or part not in {item.name for item in current.iterdir()}:
            return False
        current = current / part
    return current.exists()


def check_paths(root: Path) -> list[str]:
    root = root.resolve()
    ledger_path = root / "docs/development/documentation-migration-map.json"
    migration: dict[str, str] = {}
    if ledger_path.exists():
        payload = json.loads(ledger_path.read_text(encoding="utf-8"))
        migration = {
            item["old_path"]: item["new_path"]
            for item in payload["entries"]
            if item["old_path"] != item["new_path"]
        }
    errors: list[str] = []
    files = [root / "README.md", *sorted((root / "docs").rglob("*.md"))]
    for source in files:
        text = source.read_text(encoding="utf-8")
        for target, line in extract_targets(text):
            if _is_external(target) or target.startswith("#"):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            candidate = (source.parent / target).resolve()
            if _case_sensitive_path(root, candidate):
                continue
            old_rel = candidate.relative_to(root).as_posix() if candidate.is_relative_to(root) else ""
            mapped = migration.get(old_rel)
            source_rel = source.relative_to(root).as_posix()
            mapped = mapped or _HISTORICAL_LINK_EXCEPTIONS.get((source_rel, target))
            if mapped and _case_sensitive_path(root, root / mapped):
                continue
            errors.append(f"{source.relative_to(root).as_posix()}:{line}: missing local target {target}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = check_paths(args.root)
    if errors:
        print("\n".join(errors))
        return 1
    print("documentation local links: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
