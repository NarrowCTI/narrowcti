"""Standard STIX indicator-pattern construction.

The function deliberately preserves the historical NarrowCTI mapping.  It
does not know about OpenCTI, source adapters or graph persistence.
"""

from __future__ import annotations

from collections.abc import Mapping


def escape_pattern_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def indicator_pattern(raw_indicator: Mapping[str, object]) -> str | None:
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


__all__ = ["escape_pattern_value", "indicator_pattern"]
