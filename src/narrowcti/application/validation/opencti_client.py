"""Provider-neutral OpenCTI client compatibility validation."""

from __future__ import annotations


DEFAULT_REPORT_NAME = "NarrowCTI v1.0 OpenCTI client compatibility validation"

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


def import_validation_report(
    api_client,
    report_name,
    *,
    bundle_builder,
    bundle_importer,
):
    bundle, _ = bundle_builder(
        report_name,
        "Controlled NarrowCTI client compatibility validation Report.",
        0,
        [],
        identity_name="NarrowCTI Gateway",
    )
    rejected = []
    imported_counts = []
    serialized_bundle = bundle.serialize()
    for _ in range(2):
        imported, failed = bundle_importer(serialized_bundle, update=True)
        imported_counts.append(len(imported or []))
        rejected.extend(failed or [])
    return {
        "imported_counts": imported_counts,
        "rejected_count": len(rejected),
        "exact_report_count": len(exact_report_matches(api_client, report_name)),
    }


__all__ = [
    "DEFAULT_REPORT_NAME", "REPORT_LOOKUP_QUERY",
    "validate_authentication",
    "exact_report_matches",
    "import_validation_report",
]
