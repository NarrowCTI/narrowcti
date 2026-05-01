from exporters.stix_builder import build_report_bundle


def send_bundle(
    api_client,
    name,
    description,
    score,
    indicators=None,
    identity_name="OTX Gateway",
):
    bundle, indicator_count = build_report_bundle(
        name,
        description,
        score,
        indicators,
        identity_name=identity_name,
    )
    api_client.stix2.import_bundle_from_json(bundle.serialize(), update=True)
    return indicator_count
