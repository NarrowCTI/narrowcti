import json
import os
from datetime import datetime, timezone

from core.atomic_io import write_json_atomic
from narrowcti.domain.intelligence.indicator_types import (
    LOWERCASE_VALUE_TYPES,
    TYPE_ALIASES,
    normalize_indicator_type,
    normalize_indicator_value,
)

__all__ = [
    "ARTIFACTS_KEY",
    "ARTIFACT_RECORDS_KEY",
    "ArtifactDeduplicationIndex",
    "LOWERCASE_VALUE_TYPES",
    "TYPE_ALIASES",
    "default_artifact_state",
    "indicator_fingerprint",
    "load_artifact_state",
    "normalize_artifact_state",
    "normalize_indicator_type",
    "normalize_indicator_value",
    "save_artifact_state",
    "source_sighting_key",
    "utc_now",
]


ARTIFACTS_KEY = "artifact_fingerprints"
ARTIFACT_RECORDS_KEY = "artifact_records"

def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def indicator_fingerprint(indicator):
    indicator_type = normalize_indicator_type(indicator.get("type"))
    indicator_value = normalize_indicator_value(
        indicator_type,
        indicator.get("indicator"),
    )
    if not indicator_type or not indicator_value:
        return None
    return f"{indicator_type}:{indicator_value}"


def default_artifact_state():
    return {ARTIFACTS_KEY: [], ARTIFACT_RECORDS_KEY: {}}


def normalize_artifact_state(data):
    if not isinstance(data, dict):
        return default_artifact_state()
    if ARTIFACTS_KEY not in data or not isinstance(data[ARTIFACTS_KEY], list):
        data[ARTIFACTS_KEY] = []
    if ARTIFACT_RECORDS_KEY not in data or not isinstance(
        data[ARTIFACT_RECORDS_KEY],
        dict,
    ):
        data[ARTIFACT_RECORDS_KEY] = {}
    return data


def load_artifact_state(state_file):
    if not os.path.exists(state_file):
        return default_artifact_state()

    with open(state_file, "r") as f:
        try:
            data = json.load(f)
        except Exception:
            return default_artifact_state()

    return normalize_artifact_state(data)


def save_artifact_state(state_file, state):
    write_json_atomic(state_file, state, normalize=normalize_artifact_state)


def source_sighting_key(sighting):
    return (
        str(sighting.get("source_key") or ""),
        str(sighting.get("external_id") or ""),
    )


class ArtifactDeduplicationIndex:
    def __init__(self, state_file):
        self.state_file = state_file
        self.state = load_artifact_state(state_file)

    def refresh(self):
        self.state = load_artifact_state(self.state_file)

    def has_fingerprint(self, fingerprint):
        self.refresh()
        return fingerprint in self.state[ARTIFACTS_KEY]

    def artifact_record(self, fingerprint):
        self.refresh()
        record = self.state[ARTIFACT_RECORDS_KEY].get(fingerprint)
        return dict(record) if isinstance(record, dict) else None

    def correlation_summary(self, indicators):
        self.refresh()
        records = self.state[ARTIFACT_RECORDS_KEY]
        fingerprints = []
        sources = set()

        for indicator in indicators or []:
            fingerprint = indicator_fingerprint(indicator)
            if not fingerprint:
                continue
            fingerprints.append(fingerprint)
            record = records.get(fingerprint) or {}
            sources.update(record.get("sources") or [])

        known = [
            fingerprint
            for fingerprint in fingerprints
            if fingerprint in self.state[ARTIFACTS_KEY]
        ]
        return {
            "fingerprints": fingerprints,
            "known_count": len(known),
            "known_fingerprints": known,
            "sources": sorted(sources),
        }

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

    def mark_indicators(
        self,
        indicators,
        source_key="",
        external_id="",
        title="",
    ):
        self.refresh()
        known = set(self.state[ARTIFACTS_KEY])
        records = self.state[ARTIFACT_RECORDS_KEY]
        added = 0
        changed = False
        now = utc_now()
        source_key = str(source_key or "").strip()
        external_id = str(external_id or "").strip()
        title = str(title or "").strip()

        for indicator in indicators:
            fingerprint = indicator_fingerprint(indicator)
            if not fingerprint:
                continue

            if fingerprint not in known:
                self.state[ARTIFACTS_KEY].append(fingerprint)
                known.add(fingerprint)
                added += 1
                changed = True

            record = records.get(fingerprint)
            if not isinstance(record, dict):
                record = {
                    "fingerprint": fingerprint,
                    "first_seen": now,
                    "last_seen": now,
                    "sources": [],
                    "sightings": [],
                }
                records[fingerprint] = record
                changed = True

            if not record.get("first_seen"):
                record["first_seen"] = now
                changed = True
            if record.get("last_seen") != now:
                record["last_seen"] = now
                changed = True

            sources = record.setdefault("sources", [])
            if source_key and source_key not in sources:
                sources.append(source_key)
                sources.sort()
                changed = True

            sightings = record.setdefault("sightings", [])
            if source_key or external_id or title:
                sighting = {
                    "source_key": source_key,
                    "external_id": external_id,
                    "title": title,
                    "recorded_at": now,
                }
                sighting_key = source_sighting_key(sighting)
                exists = any(
                    source_sighting_key(existing) == sighting_key
                    for existing in sightings
                    if isinstance(existing, dict)
                )
                if not exists:
                    sightings.append(sighting)
                    changed = True

        if changed:
            save_artifact_state(self.state_file, self.state)
        return added
