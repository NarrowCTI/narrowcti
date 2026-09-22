"""Compatibility/composition surface for OpenCTI relationship audits."""

from __future__ import annotations
# ruff: noqa: F403, F405

import argparse
import json
import os
import sys

from narrowcti.application.assurance.opencti_relationship_audit import *  # noqa: F403
from narrowcti.adapters.opencti.relationship_audit import *  # noqa: F403

def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only OpenCTI object relationship and Diamond context audit."
    )
    parser.add_argument("--opencti-url", default=os.getenv("OPENCTI_URL", ""))
    parser.add_argument("--opencti-token", default=os.getenv("OPENCTI_TOKEN", ""))
    parser.add_argument(
        "--type",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_TYPE", ""),
    )
    parser.add_argument(
        "--search",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_SEARCH", ""),
    )
    parser.add_argument(
        "--first",
        type=int,
        default=int(os.getenv("NARROWCTI_OPENCTI_AUDIT_FIRST", "100")),
    )
    parser.add_argument(
        "--output-file",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_OUTPUT_FILE", ""),
    )
    parser.add_argument(
        "--expected-quadrants",
        default=os.getenv("NARROWCTI_OPENCTI_AUDIT_EXPECTED_QUADRANTS", ""),
        help="Comma-separated Diamond quadrants expected for this target.",
    )
    parser.add_argument(
        "--require-kill-chain",
        action=argparse.BooleanOptionalAction,
        default=env_bool("NARROWCTI_OPENCTI_AUDIT_REQUIRE_KILL_CHAIN", False),
        help="Require at least one direct ATT&CK Attack Pattern in the audit.",
    )
    return parser.parse_args(argv)


def ensure_utf8_stdout():
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


def main(argv=None):
    ensure_utf8_stdout()
    args = parse_args(argv)
    if not args.opencti_url:
        raise SystemExit("Missing --opencti-url or OPENCTI_URL")
    if not args.opencti_token:
        raise SystemExit("Missing --opencti-token or OPENCTI_TOKEN")
    if not args.type:
        raise SystemExit("Missing --type or NARROWCTI_OPENCTI_AUDIT_TYPE")
    if args.type not in TARGET_QUERIES:
        valid_types = ", ".join(sorted(TARGET_QUERIES))
        raise SystemExit(f"Invalid --type {args.type!r}. Valid values: {valid_types}")
    if not args.search:
        raise SystemExit("Missing --search or NARROWCTI_OPENCTI_AUDIT_SEARCH")
    report = build_relationship_audit(
        args.opencti_url,
        args.opencti_token,
        args.type,
        args.search,
        first=args.first,
        expected_quadrants=normalize_quadrants(args.expected_quadrants),
        require_kill_chain=args.require_kill_chain,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output_file:
        parent = os.path.dirname(args.output_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.output_file, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    print(rendered)




if __name__ == "__main__":
    main()
