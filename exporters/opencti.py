from core.graph_export_plan import normalize_graph_export_mode
from exporters.stix_builder import build_curated_report_bundle, build_report_bundle


def send_bundle(
    api_client,
    name,
    description,
    score,
    indicators=None,
    identity_name="NarrowCTI Gateway",
    graph_candidate_policy=None,
    graph_export_mode="audit",
):
    if normalize_graph_export_mode(graph_export_mode) == "export":
        bundle, indicator_count, _ = build_curated_report_bundle(
            name,
            description,
            score,
            indicators,
            graph_candidate_policy=graph_candidate_policy,
            identity_name=identity_name,
        )
    else:
        bundle, indicator_count = build_report_bundle(
            name,
            description,
            score,
            indicators,
            identity_name=identity_name,
        )
    api_client.stix2.import_bundle_from_json(bundle.serialize(), update=True)
    return indicator_count
