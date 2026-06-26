from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256

from core.graph_evidence import GRAPH_EVIDENCE_VERSION, clamp_confidence


GRAPH_CANDIDATE_VERSION = GRAPH_EVIDENCE_VERSION

SAFE_GRAPH_EXPORT_ENTITY_TYPES = (
    "attack_data_component",
    "attack_data_source",
    "attack_pattern",
    "artifact",
    "autonomous_system",
    "campaign",
    "channel",
    "course_of_action",
    "detection_guidance",
    "detection_rule",
    "event",
    "event_report",
    "infrastructure",
    "intrusion_set",
    "malware",
    "object_reference",
    "observable",
    "sighting",
    "security_platform",
    "target_administrative_area",
    "target_city",
    "target_country",
    "target_individual",
    "target_organization",
    "target_position",
    "target_region",
    "target_sector",
    "target_system",
    "threat_actor",
    "threat_actor_individual",
    "tool",
    "narrative",
    "vulnerability",
)

SAFE_GRAPH_EXPORT_STIX_OBJECT_TYPES = (
    "attack-pattern",
    "autonomous-system",
    "campaign",
    "channel",
    "course-of-action",
    "event",
    "identity",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "narrative",
    "note",
    "observable",
    "relationship",
    "sighting",
    "security-platform",
    "threat-actor",
    "tool",
    "vulnerability",
    "x-mitre-data-component",
    "x-mitre-data-source",
)


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
    relationship_confidence: int = 50
    display_name: str = ""
    provenance: Mapping[str, object] = field(default_factory=dict)
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
            relationship_type=self.relationship_type,
            attributes=self.attributes,
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
            "relationship_confidence": self.relationship_confidence,
        }
        if self.display_name:
            candidate["display_name"] = self.display_name
        if self.provenance:
            candidate["provenance"] = dict(self.provenance)
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


@dataclass(frozen=True)
class GraphCandidatePolicyResult:
    version: str
    candidate_count: int
    accepted: tuple[GraphCandidate, ...] = ()
    held: tuple[Mapping[str, object], ...] = ()

    @property
    def accepted_count(self):
        return len(self.accepted)

    @property
    def held_count(self):
        return len(self.held)

    @property
    def held_reasons(self):
        reasons = Counter()
        for item in self.held:
            for reason in item.get("reasons") or []:
                reasons[reason] += 1
        return dict(sorted(reasons.items()))

    def to_dict(self):
        return {
            "version": self.version,
            "candidate_count": self.candidate_count,
            "accepted_count": self.accepted_count,
            "held_count": self.held_count,
            "held_reasons": self.held_reasons,
            "accepted": [candidate.to_dict() for candidate in self.accepted],
            "held": [dict(item) for item in self.held],
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


def apply_graph_candidate_policy(
    candidate_set,
    min_entity_confidence=0,
    min_relationship_confidence=0,
    allowed_entity_types=None,
    allowed_stix_object_types=None,
    require_relationship_provenance=False,
):
    allowed_entity_types = normalize_exclusions(allowed_entity_types)
    allowed_stix_object_types = normalize_exclusions(allowed_stix_object_types)
    accepted = []
    held = []

    for candidate in candidate_set.candidates:
        reasons = graph_candidate_policy_reasons(
            candidate,
            min_entity_confidence=min_entity_confidence,
            min_relationship_confidence=min_relationship_confidence,
            allowed_entity_types=allowed_entity_types,
            allowed_stix_object_types=allowed_stix_object_types,
            require_relationship_provenance=require_relationship_provenance,
        )
        if reasons:
            held.append(
                {
                    "candidate": candidate.to_dict(),
                    "reasons": reasons,
                }
            )
        else:
            accepted.append(candidate)

    return GraphCandidatePolicyResult(
        version=candidate_set.version,
        candidate_count=candidate_set.candidate_count,
        accepted=tuple(accepted),
        held=tuple(held),
    )


def graph_candidate_policy_reasons(
    candidate,
    min_entity_confidence=0,
    min_relationship_confidence=0,
    allowed_entity_types=None,
    allowed_stix_object_types=None,
    require_relationship_provenance=False,
):
    reasons = []
    if candidate.confidence < min_entity_confidence:
        reasons.append("entity_confidence_below_min")
    if candidate.relationship_confidence < min_relationship_confidence:
        reasons.append("relationship_confidence_below_min")
    if allowed_entity_types and candidate.entity_type not in allowed_entity_types:
        reasons.append("entity_type_not_allowed")
    if (
        allowed_stix_object_types
        and candidate.stix_object_type not in allowed_stix_object_types
    ):
        reasons.append("stix_object_type_not_allowed")
    if require_relationship_provenance and not candidate.provenance:
        reasons.append("relationship_provenance_required")
    return reasons


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
        relationship_confidence=clamp_confidence(
            record.get("relationship_confidence", record.get("confidence"))
        ),
        display_name=clean_string(record.get("display_name")),
        provenance=candidate_provenance(record, default_source_key),
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
    relationship_type="",
    attributes=None,
):
    source_type, source_value = relationship_source_anchor(attributes)
    material = "|".join(
        [
            clean_string(source_key).lower(),
            clean_string(external_id).lower(),
            clean_string(entity_type).lower(),
            clean_string(stix_object_type).lower(),
            clean_string(value).lower(),
            clean_string(relationship_type).lower(),
            source_type,
            source_value,
        ]
    )
    return sha256(material.encode("utf-8")).hexdigest()


def relationship_source_anchor(attributes):
    attributes = compact_mapping(attributes)
    return (
        first_clean_value(
            attributes.get("relationship_source_stix_object_type"),
            attributes.get("source_stix_object_type"),
            attributes.get("parent_cluster_type"),
            attributes.get("parent_galaxy_type"),
        ).lower(),
        first_clean_value(
            attributes.get("relationship_source_value"),
            attributes.get("source_value"),
            attributes.get("parent_cluster_value"),
        ).lower(),
    )


def compact_mapping(value):
    if not isinstance(value, Mapping):
        return {}
    return {
        clean_string(key): item
        for key, item in value.items()
        if clean_string(key) and item not in ("", None, [], {})
    }


def normalize_exclusions(values):
    if isinstance(values, str):
        values = values.split(",")
    return {clean_string(value) for value in values or [] if clean_string(value)}


def safe_graph_export_allowed_entity_types(export_mode, configured_values=None):
    configured = normalize_exclusions(configured_values)
    if configured:
        return sorted(configured)
    if clean_string(export_mode).lower() == "export":
        return list(SAFE_GRAPH_EXPORT_ENTITY_TYPES)
    return []


def safe_graph_export_allowed_stix_object_types(export_mode, configured_values=None):
    configured = normalize_exclusions(configured_values)
    if configured:
        return sorted(configured)
    if clean_string(export_mode).lower() == "export":
        return list(SAFE_GRAPH_EXPORT_STIX_OBJECT_TYPES)
    return []


def candidate_provenance(record, default_source_key=""):
    provenance = compact_mapping(record.get("provenance"))
    source_key = clean_string(record.get("source_key")) or clean_string(default_source_key)
    source_name = clean_string(record.get("source_name"))
    source_field = clean_string(record.get("source_field"))
    if source_key:
        provenance.setdefault("source_key", source_key)
    if source_name:
        provenance.setdefault("source_name", source_name)
    if source_field:
        provenance.setdefault("source_field", source_field)
    return provenance


def clean_string(value):
    return " ".join(str(value or "").strip().split())


def first_clean_value(*values):
    for value in values:
        cleaned = clean_string(value)
        if cleaned:
            return cleaned
    return ""
