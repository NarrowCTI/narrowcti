#!/usr/bin/env python3
"""Generate a deterministic inventory from an immutable Git tree.

The W0 baseline is the release object database, not the checkout.  This
script therefore resolves the requested ref, enumerates its tree with
``git ls-tree`` and reads blob contents with ``git cat-file``.  Files added
to the working tree after the release cannot change the result for
``--ref v1.1.1``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


CANONICAL_V1_1_1_COMMIT = "4e3509b8f18c330361994975ab3c5b11e8f5b05f"


class InventoryError(RuntimeError):
    """Raised when the Git object database cannot provide the baseline."""


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=text,
    )
    if result.returncode:
        detail = result.stderr if text else result.stderr.decode("utf-8", "replace")
        raise InventoryError(f"git {' '.join(args)} failed: {detail.strip()}")
    return result.stdout


def resolve_repo(repo_arg: str | None) -> Path:
    requested = Path(repo_arg).resolve() if repo_arg else Path.cwd()
    root = str(git(requested, "rev-parse", "--show-toplevel")).strip()
    return Path(root).resolve()


def resolve_commit(repo: Path, ref: str) -> str:
    return str(git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")).strip()


def resolve_tree(repo: Path, ref: str) -> str:
    return str(git(repo, "rev-parse", "--verify", f"{ref}^{{tree}}")).strip()


def tree_entries(repo: Path, tree: str) -> list[dict[str, str]]:
    raw = git(repo, "ls-tree", "--full-tree", "-r", "-z", tree, text=False)
    entries: list[dict[str, str]] = []
    for record in bytes(raw).split(b"\0"):
        if not record:
            continue
        header, path_bytes = record.split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ", 2)
        entries.append(
            {
                "path": path_bytes.decode("utf-8", "surrogateescape"),
                "mode": mode,
                "object_type": object_type,
                "object_id": object_id,
            }
        )
    return entries


def blob_metadata(repo: Path, object_ids: list[str]) -> dict[str, tuple[int, str]]:
    """Read blob bytes through one Git batch process and hash them in memory."""
    if not object_ids:
        return {}
    result = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        input=("\n".join(object_ids) + "\n").encode("ascii"),
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace")
        raise InventoryError(f"git cat-file --batch failed: {detail.strip()}")

    output = result.stdout
    offset = 0
    metadata: dict[str, tuple[int, str]] = {}
    for object_id in object_ids:
        line_end = output.find(b"\n", offset)
        if line_end < 0:
            raise InventoryError(f"git cat-file --batch returned no header for {object_id}")
        header = output[offset:line_end].decode("ascii", "replace")
        offset = line_end + 1
        parts = header.split(" ")
        if len(parts) != 3 or parts[0] != object_id or parts[1] != "blob":
            raise InventoryError(f"git cat-file --batch returned invalid object: {header}")
        size = int(parts[2])
        content = output[offset : offset + size]
        if len(content) != size:
            raise InventoryError(f"git cat-file --batch truncated blob {object_id}")
        offset += size
        if output[offset : offset + 1] != b"\n":
            raise InventoryError(f"git cat-file --batch missing separator for {object_id}")
        offset += 1
        metadata[object_id] = (size, hashlib.sha256(content).hexdigest())
    return metadata


def inventory_entry(
    entry: dict[str, str],
    blobs: dict[str, tuple[int, str]],
) -> dict[str, object]:
    result: dict[str, object] = {
        "path": entry["path"],
        "mode": entry["mode"],
        "object_type": entry["object_type"],
        "object_id": entry["object_id"],
    }
    if entry["object_type"] == "blob":
        size, digest = blobs[entry["object_id"]]
        result["size"] = size
        result["sha256"] = digest
    else:
        result["size"] = None
        result["sha256"] = None
    return result


def build_inventory(repo: Path, ref: str, expected_commit: str | None = None) -> dict[str, object]:
    commit = resolve_commit(repo, ref)
    expected = expected_commit
    if expected is None and ref == "v1.1.1":
        expected = CANONICAL_V1_1_1_COMMIT
    if expected and commit != expected:
        raise InventoryError(
            f"{ref} resolves to {commit}, expected canonical commit {expected}"
        )

    tree = resolve_tree(repo, ref)
    raw_entries = tree_entries(repo, tree)
    blob_ids = [item["object_id"] for item in raw_entries if item["object_type"] == "blob"]
    blobs = blob_metadata(repo, blob_ids)
    entries = [inventory_entry(item, blobs) for item in raw_entries]
    entries.sort(key=lambda item: str(item["path"]))
    return {
        "schema": "narrowcti.w0.baseline-inventory/v1",
        "ref": ref,
        "commit": commit,
        "tree": tree,
        "entry_count": len(entries),
        "entries": entries,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="v1.1.1", help="Git ref to inventory")
    parser.add_argument(
        "--expected-commit",
        help="Optional commit that the ref must resolve to",
    )
    parser.add_argument(
        "--repo",
        help="Repository path; defaults to the current Git worktree",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON to this path instead of stdout",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        repo = resolve_repo(args.repo)
        inventory = build_inventory(repo, args.ref, args.expected_commit)
    except (InventoryError, OSError, ValueError) as exc:
        print(f"baseline inventory error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(inventory, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        destination = args.output if args.output.is_absolute() else Path.cwd() / args.output
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
