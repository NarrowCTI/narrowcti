"""Canonical indicator type and value normalization.

This module is deliberately dependency-light.  Stateful artifact
deduplication consumes this contract but does not own its aliases or case
normalization tables.
"""

TYPE_ALIASES = {
    "domain-name": "domain",
    "domain": "domain",
    "hostname": "hostname",
    "ipv4": "ipv4",
    "ipv4-addr": "ipv4",
    "ip": "ipv4",
    "ipv6": "ipv6",
    "ipv6-addr": "ipv6",
    "url": "url",
    "uri": "url",
    "email": "email",
    "email-addr": "email",
    "filehash-md5": "filehash-md5",
    "md5": "filehash-md5",
    "filehash-sha1": "filehash-sha1",
    "sha1": "filehash-sha1",
    "filehash-sha256": "filehash-sha256",
    "sha256": "filehash-sha256",
}

LOWERCASE_VALUE_TYPES = {
    "domain",
    "hostname",
    "email",
    "filehash-md5",
    "filehash-sha1",
    "filehash-sha256",
}


def normalize_indicator_type(value):
    indicator_type = str(value or "").strip().lower()
    return TYPE_ALIASES.get(indicator_type, indicator_type)


def normalize_indicator_value(indicator_type, value):
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    if indicator_type in LOWERCASE_VALUE_TYPES:
        return normalized.lower()
    return normalized
