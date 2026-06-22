from core.deduplication import normalize_indicator_type


def normalize_allowed_indicator_types(values):
    return tuple(
        value
        for value in (normalize_indicator_type(item) for item in values or ())
        if value
    )


def filter_indicators_by_type(indicators, allowed_types):
    allowed = set(normalize_allowed_indicator_types(allowed_types))
    if not allowed:
        return list(indicators or ()), 0

    filtered = []
    dropped = 0
    for indicator in indicators or ():
        indicator_type = normalize_indicator_type(indicator.get("type"))
        if indicator_type in allowed:
            filtered.append(indicator)
        else:
            dropped += 1
    return filtered, dropped
