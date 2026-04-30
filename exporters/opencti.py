from datetime import datetime, timezone
from stix2 import Bundle, Report, Identity


def send_bundle(api_client, name, description, score):
    identity = Identity(name="OTX Gateway", identity_class="organization")

    report = Report(
        name=name,
        description=description,
        report_types=["threat-report"],
        confidence=score,
        created=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
    )

    bundle = Bundle(objects=[identity, report], allow_custom=True)
    api_client.stix2.import_bundle_from_json(bundle.serialize(), update=True)
