from datetime import datetime, timezone

from stix2 import Bundle, Identity, Indicator, Report


def escape_pattern_value(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def indicator_pattern(raw_indicator):
    value = raw_indicator.get("indicator")
    indicator_type = raw_indicator.get("type", "").lower()

    if not value:
        return None

    escaped = escape_pattern_value(value)
    pattern_by_type = {
        "domain": f"[domain-name:value = '{escaped}']",
        "hostname": f"[domain-name:value = '{escaped}']",
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
        "email": f"[email-addr:value = '{escaped}']",
        "filehash-md5": f"[file:hashes.MD5 = '{escaped}']",
        "filehash-sha1": f"[file:hashes.SHA1 = '{escaped}']",
        "filehash-sha256": f"[file:hashes.SHA256 = '{escaped}']",
    }
    return pattern_by_type.get(indicator_type)


def build_indicators(raw_indicators, identity_id, score, valid_from):
    objects = []
    seen_patterns = set()

    for raw_indicator in raw_indicators:
        pattern = indicator_pattern(raw_indicator)
        if not pattern or pattern in seen_patterns:
            continue

        seen_patterns.add(pattern)
        value = raw_indicator.get("indicator")
        objects.append(
            Indicator(
                name=value,
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                confidence=score,
                created_by_ref=identity_id,
            )
        )

    return objects


def build_report_bundle(
    name,
    description,
    score,
    indicators=None,
    identity_name="NarrowCTI OTX Connector",
):
    now = datetime.now(timezone.utc)
    identity = Identity(name=identity_name, identity_class="organization")
    indicator_objects = build_indicators(indicators or [], identity.id, score, now)
    object_refs = [indicator.id for indicator in indicator_objects] or [identity.id]

    report = Report(
        name=name,
        description=description or "",
        report_types=["threat-report"],
        confidence=score,
        created=now,
        modified=now,
        published=now,
        created_by_ref=identity.id,
        object_refs=object_refs,
    )

    bundle = Bundle(objects=[identity, *indicator_objects, report], allow_custom=True)
    return bundle, len(indicator_objects)
