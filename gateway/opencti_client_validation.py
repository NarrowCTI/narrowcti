import argparse
import os

import pycti

from exporters.stix_builder import build_report_bundle
from gateway.opencti_client import build_opencti_client


DEFAULT_REPORT_NAME = "NarrowCTI v0.9 OpenCTI client compatibility validation"

REPORT_LOOKUP_QUERY = """
query NarrowCTIClientValidationReport($search: String!) {
  reports(first: 20, search: $search) {
    edges {
      node {
        id
        standard_id
        name
      }
    }
  }
}
"""


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
    environ = environ or os.environ
    opencti_url = str(environ.get("OPENCTI_URL") or "").strip()
    opencti_token = str(environ.get("OPENCTI_TOKEN") or "").strip()
    if not opencti_url or not opencti_token:
        raise ValueError("OPENCTI_URL and OPENCTI_TOKEN are required")
    return build_opencti_client(opencti_url, opencti_token)


def validate_authentication(api_client):
    result = api_client.query("query NarrowCTIClientValidation { me { id } }")
    return bool(((result.get("data") or {}).get("me") or {}).get("id"))


def exact_report_matches(api_client, report_name):
    result = api_client.query(REPORT_LOOKUP_QUERY, {"search": report_name})
    edges = (((result.get("data") or {}).get("reports") or {}).get("edges")) or []
    return [
        edge.get("node") or {}
        for edge in edges
        if str((edge.get("node") or {}).get("name") or "") == report_name
    ]


def import_validation_report(api_client, report_name):
    bundle, _ = build_report_bundle(
        report_name,
        "Controlled NarrowCTI client compatibility validation Report.",
        0,
        [],
        identity_name="NarrowCTI Gateway",
    )
    rejected = []
    imported_counts = []
    for _ in range(2):
        imported, failed = api_client.stix2.import_bundle_from_json(
            bundle.serialize(),
            update=True,
        )
        imported_counts.append(len(imported or []))
        rejected.extend(failed or [])
    return {
        "imported_counts": imported_counts,
        "rejected_count": len(rejected),
        "exact_report_count": len(exact_report_matches(api_client, report_name)),
    }


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
