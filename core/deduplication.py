import json
import os


ARTIFACTS_KEY = "artifact_fingerprints"

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


def indicator_fingerprint(indicator):
    indicator_type = normalize_indicator_type(indicator.get("type"))
    indicator_value = normalize_indicator_value(
        indicator_type,
        indicator.get("indicator"),
    )
    if not indicator_type or not indicator_value:
        return None
    return f"{indicator_type}:{indicator_value}"


def load_artifact_state(state_file):
    if not os.path.exists(state_file):
        return {ARTIFACTS_KEY: []}

    with open(state_file, "r") as f:
        try:
            data = json.load(f)
        except Exception:
            return {ARTIFACTS_KEY: []}

    if not isinstance(data, dict):
        return {ARTIFACTS_KEY: []}
    if ARTIFACTS_KEY not in data or not isinstance(data[ARTIFACTS_KEY], list):
        data[ARTIFACTS_KEY] = []
    return data


def save_artifact_state(state_file, state):
    directory = os.path.dirname(state_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(state_file, "w") as f:
        json.dump(state, f)


class ArtifactDeduplicationIndex:
    def __init__(self, state_file):
        self.state_file = state_file
        self.state = load_artifact_state(state_file)

    def refresh(self):
        self.state = load_artifact_state(self.state_file)

    def has_fingerprint(self, fingerprint):
        self.refresh()
        return fingerprint in self.state[ARTIFACTS_KEY]

    def filter_new_indicators(self, indicators):
        self.refresh()
        known = set(self.state[ARTIFACTS_KEY])
        filtered = []
        duplicate_count = 0

        for indicator in indicators:
            fingerprint = indicator_fingerprint(indicator)
            if fingerprint and fingerprint in known:
                duplicate_count += 1
                continue
            filtered.append(indicator)

        return filtered, duplicate_count

    def mark_indicators(self, indicators):
        self.refresh()
        known = set(self.state[ARTIFACTS_KEY])
        added = 0

        for indicator in indicators:
            fingerprint = indicator_fingerprint(indicator)
            if not fingerprint or fingerprint in known:
                continue
            self.state[ARTIFACTS_KEY].append(fingerprint)
            known.add(fingerprint)
            added += 1

        if added:
            save_artifact_state(self.state_file, self.state)
        return added
