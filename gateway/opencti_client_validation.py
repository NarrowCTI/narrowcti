"""Compatibility/composition surface for OpenCTI client validation."""

from __future__ import annotations

import argparse
import pycti

from core.runtime_config import environment, load_opencti_config
from exporters.stix_builder import build_report_bundle
from gateway.opencti_client import build_opencti_client
from narrowcti.application.validation.opencti_client import (
    DEFAULT_REPORT_NAME,
    validate_authentication,
)
from narrowcti.application.validation.opencti_client import (
    import_validation_report as _import_validation_report,
)

def import_validation_report(api_client, report_name):
    return _import_validation_report(
        api_client,
        report_name,
        bundle_builder=build_report_bundle,
        bundle_importer=api_client.stix2.import_bundle_from_json,
    )

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate the NarrowCTI OpenCTI client boundary."
    )
    parser.add_argument(
        "--write-test",
        action="store_true",
        help="Import the deterministic compatibility Report twice.",
    )
    parser.add_argument(
        "--report-name",
        default=DEFAULT_REPORT_NAME,
        help="Deterministic Report name used by the explicit write test.",
    )
    return parser.parse_args(argv)


def build_client(environ=None):
    try:
        config = load_opencti_config(environment(environ), required=True)
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc
    return build_opencti_client(config.url, config.token)


def main(argv=None):
    args = parse_args(argv)
    try:
        api_client = build_client()
    except ValueError as exc:
        raise SystemExit(str(exc)) from None

    authenticated = validate_authentication(api_client)
    print(f"pycti_version={pycti.__version__}")
    print(f"authenticated={str(authenticated).lower()}")
    if not authenticated:
        raise SystemExit("OpenCTI authentication validation failed")

    if args.write_test:
        result = import_validation_report(api_client, args.report_name)
        print(f"first_imported={result['imported_counts'][0]}")
        print(f"second_imported={result['imported_counts'][1]}")
        print(f"rejected={result['rejected_count']}")
        print(f"exact_report_count={result['exact_report_count']}")
        if result["rejected_count"] or result["exact_report_count"] != 1:
            raise SystemExit("OpenCTI write compatibility validation failed")

    return 0




if __name__ == "__main__":
    main()
