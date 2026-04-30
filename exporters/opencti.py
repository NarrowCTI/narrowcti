from exporters.stix_builder import build_report_bundle


def send_bundle(api_client, name, description, score, indicators=None):
    bundle, indicator_count = build_report_bundle(name, description, score, indicators)
    api_client.stix2.import_bundle_from_json(bundle.serialize(), update=True)
    return indicator_count
