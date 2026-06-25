from core.feed_contract import slugify


DEFAULT_CURATION_IDENTITY_NAME = "NarrowCTI Gateway"

CANONICAL_SOURCE_IDENTITIES = {
    "alienvault:otx": "OTX AlienVault",
    "alienvault:otx-premium": "OTX AlienVault Premium",
    "misp:misp": "MISP",
}


def source_identity_name(
    source_key="",
    source_name="",
    provider="",
    fallback=DEFAULT_CURATION_IDENTITY_NAME,
):
    key = clean_value(source_key).lower()
    if key in CANONICAL_SOURCE_IDENTITIES:
        return CANONICAL_SOURCE_IDENTITIES[key]

    name = clean_value(source_name)
    provider_name = clean_value(provider)
    if name and provider_name:
        if slugify(name) == slugify(provider_name):
            return provider_name
        return f"{name} {provider_name}"
    if name:
        return name
    if provider_name:
        return provider_name
    return fallback


def feed_source_identity_name(source, fallback=DEFAULT_CURATION_IDENTITY_NAME):
    if not source:
        return fallback
    return source_identity_name(
        getattr(source, "key", ""),
        getattr(source, "name", ""),
        getattr(source, "provider", ""),
        fallback=fallback,
    )


def clean_value(value):
    return str(value or "").strip()
