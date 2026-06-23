from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256

from core.graph_evidence import GRAPH_EVIDENCE_VERSION, clamp_confidence


GRAPH_CANDIDATE_VERSION = GRAPH_EVIDENCE_VERSION


@dataclass(frozen=True)
class GraphCandidate:
    entity_type: str
    value: str
    stix_object_type: str
    relationship_type: str
    source_key: str = ""
    source_name: str = ""
    source_field: str = ""
    confidence: int = 50
    display_name: str = ""
    attributes: Mapping[str, object] = field(default_factory=dict)
    external_id: str = ""
    title: str = ""

    @property
    def name(self):
        return self.display_name or self.value

    @property
    def fingerprint(self):
        return candidate_fingerprint(
            self.source_key,
            self.external_id,
            self.entity_type,
            self.stix_object_type,
            self.value,
        )

    def to_dict(self):
        candidate = {
            "fingerprint": self.fingerprint,
            "entity_type": self.entity_type,
            "value": self.value,
            "name": self.name,
            "stix_object_type": self.stix_object_type,
            "relationship_type": self.relationship_type,
            "source_key": self.source_key,
            "source_name": self.source_name,
            "source_field": self.source_field,
            "confidence": self.confidence,
        }
        if self.display_name:
            candidate["display_name"] = self.display_name
        if self.attributes:
            candidate["attributes"] = dict(self.attributes)
        if self.external_id:
            candidate["external_id"] = self.external_id
        if self.title:
            candidate["title"] = self.title
        return candidate


@dataclass(frozen=True)
class GraphCandidateSet:
    version: str
    source_key: str
    external_id: str
    title: str
    candidates: tuple[GraphCandidate, ...] = ()

    @property
    def candidate_count(self):
        return len(self.candidates)

    @property
    def counts(self):
        return dict(
            sorted(Counter(candidate.entity_type for candidate in self.candidates).items())
        )

    def to_dict(self):
        return {
            "version": self.version,
            "source_key": self.source_key,
            "external_id": self.external_id,
            "title": self.title,
            "candidate_count": self.candidate_count,
            "counts": self.counts,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


def build_graph_candidates(
    graph_evidence,
    min_confidence=0,
    excluded_entity_types=None,
    excluded_stix_object_types=None,
):
    graph_evidence = graph_evidence if isinstance(graph_evidence, Mapping) else {}
    source_key = clean_string(graph_evidence.get("source_key"))
    external_id = clean_string(graph_evidence.get("external_id"))
    title = clean_string(graph_evidence.get("title"))
    excluded_entity_types = normalize_exclusions(excluded_entity_types)
    excluded_stix_object_types = normalize_exclusions(excluded_stix_object_types)

    candidates = []
    for record in graph_evidence.get("records") or []:
        candidate = graph_candidate_from_record(
            record,
            default_source_key=source_key,
            external_id=external_id,
            title=title,
        )
        if not candidate:
            continue
        if candidate.confidence < min_confidence:
            continue
        if candidate.entity_type in excluded_entity_types:
            continue
        if candidate.stix_object_type in excluded_stix_object_types:
            continue
        candidates.append(candidate)

    return GraphCandidateSet(
        version=clean_string(graph_evidence.get("version")) or GRAPH_CANDIDATE_VERSION,
        source_key=source_key,
        external_id=external_id,
        title=title,
        candidates=tuple(candidates),
    )


def graph_candidate_from_record(
    record,
    default_source_key="",
    external_id="",
    title="",
):
    if not isinstance(record, Mapping):
        return None

    entity_type = clean_string(record.get("entity_type"))
    value = clean_string(record.get("value"))
    stix_object_type = clean_string(record.get("stix_object_type"))
    relationship_type = clean_string(record.get("relationship_type"))

    if not entity_type or not value or not stix_object_type:
        return None

    return GraphCandidate(
        entity_type=entity_type,
        value=value,
        stix_object_type=stix_object_type,
        relationship_type=relationship_type or "related-to",
        source_key=clean_string(record.get("source_key")) or clean_string(default_source_key),
        source_name=clean_string(record.get("source_name")),
        source_field=clean_string(record.get("source_field")),
        confidence=clamp_confidence(record.get("confidence")),
        display_name=clean_string(record.get("display_name")),
        attributes=compact_mapping(record.get("attributes")),
        external_id=clean_string(external_id),
        title=clean_string(title),
    )


def candidate_fingerprint(
    source_key,
    external_id,
    entity_type,
    stix_object_type,
    value,
):
    material = "|".join(
        [
            clean_string(source_key).lower(),
            clean_string(external_id).lower(),
            clean_string(entity_type).lower(),
            clean_string(stix_object_type).lower(),
            clean_string(value).lower(),
        ]
    )
    return sha256(material.encode("utf-8")).hexdigest()


def compact_mapping(value):
    if not isinstance(value, Mapping):
        return {}
    return {
        clean_string(key): item
        for key, item in value.items()
        if clean_string(key) and item not in ("", None, [], {})
    }


def normalize_exclusions(values):
    return {clean_string(value) for value in values or [] if clean_string(value)}


def clean_string(value):
    return " ".join(str(value or "").strip().split())
