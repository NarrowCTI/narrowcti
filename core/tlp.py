TLP_PREFIX = "tlp:"
TLP_EQUIVALENTS = {
    "clear": frozenset(("clear", "white")),
    "white": frozenset(("clear", "white")),
}


def normalize_tlp(value):
    normalized = str(value or "").strip().lower()
    if normalized.startswith(TLP_PREFIX):
        normalized = normalized[len(TLP_PREFIX) :]
    return normalized


def normalize_allowed_tlp(values):
    return tuple(
        value
        for value in (normalize_tlp(item) for item in values or ())
        if value
    )


def extract_tlp_values(tags):
    values = []
    for tag in tags or ():
        normalized = str(tag or "").strip().lower()
        if normalized.startswith(TLP_PREFIX):
            value = normalize_tlp(normalized)
            if value:
                values.append(value)
    return tuple(values)


def tlp_is_allowed(tags, allowed_tlp):
    allowed = set()
    for value in normalize_allowed_tlp(allowed_tlp):
        allowed.update(TLP_EQUIVALENTS.get(value, (value,)))
    if not allowed:
        return True, ""

    candidate_tlp = extract_tlp_values(tags)
    if not candidate_tlp:
        return True, ""

    if allowed.intersection(candidate_tlp):
        return True, ""

    return False, f"tlp not allowed: {','.join(candidate_tlp)}"
