import re
import time
from collections.abc import Mapping

from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.feed_contract import FeedRunSummary
from core.graph_candidates import apply_graph_candidate_policy, build_graph_candidates
from core.graph_deduplication import GraphDeduplicationIndex
from core.graph_evidence import build_graph_evidence
from core.graph_export_plan import build_graph_export_plan_with_known_keys
from core.indicator_policy import filter_indicators_by_type
from core.policy import PolicyConfig, should_ingest
from core.quarantine import (
    QuarantineRecord,
    QuarantineRepository,
    bounded_raw_snapshot,
)
from core.scoring import age_days, calculate_score_details
from core.state_repository import MISPEventStateRepository
from core.tlp import tlp_is_allowed
from exporters.opencti import send_bundle

from connectors.misp.feed_adapter import MISPFeedAdapter, event_to_feed_candidate
from connectors.misp.models import MISPEventCandidate


CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
DETECTION_RULE_TYPES = {"yara", "sigma", "snort", "suricata", "pcre"}


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


def compact_mapping(value):
    return dict(value) if isinstance(value, Mapping) else {}


def decision_metadata(
    candidate_ref,
    candidate=None,
    graph_candidate_policy=None,
    graph_export_mode="audit",
    graph_deduplication_index=None,
):
    event = compact_mapping(candidate.event if candidate else {})
    reference = compact_mapping(candidate_ref.raw)
    source = event or reference
    provenance = compact_mapping(source.get("provenance"))
    controls = compact_mapping(source.get("narrowcti_controls"))
    tags = source.get("tags") or candidate_ref.tags or []

    metadata = {
        "collector": provenance.get("collector") or candidate_ref.source.name,
        "original_source": provenance.get("original_source", ""),
        "misp_event_id": provenance.get("misp_event_id") or source.get("id", ""),
        "misp_event_uuid": provenance.get("misp_event_uuid") or candidate_ref.external_id,
        "tags": list(tags),
    }
    misp_galaxies = extract_misp_galaxies(source)
    if misp_galaxies:
        metadata["misp_galaxies"] = misp_galaxies
    misp_vulnerabilities = extract_misp_vulnerabilities(source, tags)
    if misp_vulnerabilities:
        metadata["misp_vulnerabilities"] = misp_vulnerabilities
    misp_event_reports = extract_misp_event_reports(source)
    if misp_event_reports:
        metadata["misp_event_reports"] = misp_event_reports
    misp_sightings = extract_misp_sightings(source)
    if misp_sightings:
        metadata["misp_sightings"] = misp_sightings
    misp_object_references = extract_misp_object_references(source)
    if misp_object_references:
        metadata["misp_object_references"] = misp_object_references
    misp_detection_rules = extract_misp_detection_rules(source)
    if misp_detection_rules:
        metadata["misp_detection_rules"] = misp_detection_rules
    if controls:
        metadata["guardrails"] = controls
    score_details = getattr(candidate, "score_details", None)
    if score_details:
        metadata["scoring"] = dict(score_details)
    metadata["graph_evidence"] = build_graph_evidence(
        metadata,
        source_key=candidate_ref.source.key,
        external_id=candidate_ref.external_id,
        title=getattr(candidate, "name", "") or candidate_ref.title,
    )
    graph_candidates = build_graph_candidates(metadata["graph_evidence"])
    metadata["graph_candidates"] = graph_candidates.to_dict()
    graph_policy = apply_graph_candidate_policy(
        graph_candidates,
        **(graph_candidate_policy or {}),
    ).to_dict()
    metadata["graph_candidate_policy"] = graph_policy
    graph_plan, known_keys, lookup_error = build_graph_export_plan_with_known_keys(
        graph_policy,
        mode=graph_export_mode,
        graph_deduplication_index=graph_deduplication_index,
    )
    metadata["graph_export_plan"] = graph_plan
    if known_keys["entity_keys"] or known_keys["relationship_keys"]:
        metadata["graph_export_plan_known_keys"] = known_keys
    if lookup_error:
        metadata["graph_export_plan_lookup_error"] = lookup_error
    return metadata


def extract_misp_galaxies(event):
    event = compact_mapping(event)
    clusters = []
    for container in misp_galaxy_containers(event):
        galaxy = compact_mapping(container.get("galaxy"))
        for cluster in container.get("clusters") or []:
            normalized = normalize_misp_galaxy_cluster(
                cluster,
                galaxy,
                container.get("source_field", "Galaxy"),
            )
            if normalized:
                clusters.append(normalized)
    return deduplicate_misp_galaxies(clusters)


def misp_galaxy_containers(event):
    containers = []
    containers.extend(galaxy_containers_from_mapping(event, "Galaxy"))
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        if isinstance(attribute, Mapping):
            containers.extend(
                galaxy_containers_from_mapping(attribute, f"Attribute[{index}].Galaxy")
            )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        if not isinstance(misp_object, Mapping):
            continue
        containers.extend(
            galaxy_containers_from_mapping(misp_object, f"Object[{object_index}].Galaxy")
        )
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            if isinstance(attribute, Mapping):
                containers.extend(
                    galaxy_containers_from_mapping(
                        attribute,
                        f"Object[{object_index}].Attribute[{attribute_index}].Galaxy",
                    )
                )
    return containers


def galaxy_containers_from_mapping(value, source_field):
    value = compact_mapping(value)
    containers = []
    for galaxy in list_values(value.get("Galaxy")):
        galaxy = compact_mapping(galaxy)
        clusters = list_values(
            galaxy.get("GalaxyCluster") or galaxy.get("GalaxyClusters")
        )
        if clusters:
            containers.append(
                {
                    "galaxy": galaxy,
                    "clusters": clusters,
                    "source_field": source_field,
                }
            )
    direct_clusters = list_values(
        value.get("GalaxyCluster") or value.get("GalaxyClusters")
    )
    if direct_clusters:
        containers.append(
            {
                "galaxy": {},
                "clusters": direct_clusters,
                "source_field": source_field.replace("Galaxy", "GalaxyCluster"),
            }
        )
    return containers


def list_values(value):
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def normalize_misp_galaxy_cluster(cluster, galaxy, source_field):
    cluster = compact_mapping(cluster)
    if not cluster:
        return {}
    galaxy = compact_mapping(galaxy)
    meta = compact_mapping(cluster.get("meta"))
    value = (
        cluster.get("value")
        or cluster.get("name")
        or cluster.get("tag_name")
        or cluster.get("uuid")
        or ""
    )
    if not value:
        return {}
    return {
        "value": value,
        "type": cluster.get("type") or galaxy.get("type") or galaxy.get("name") or "",
        "description": cluster.get("description", ""),
        "uuid": cluster.get("uuid", ""),
        "tag_name": cluster.get("tag_name", ""),
        "galaxy_type": galaxy.get("type", ""),
        "galaxy_name": galaxy.get("name", ""),
        "source_field": source_field,
        "meta": meta,
    }


def deduplicate_misp_galaxies(clusters):
    seen = set()
    deduplicated = []
    for cluster in clusters:
        key = (
            str(cluster.get("type", "")).casefold(),
            str(cluster.get("value", "")).casefold(),
            str(cluster.get("uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(cluster)
    return deduplicated


def extract_misp_vulnerabilities(event, tags=None):
    findings = []
    for source in misp_vulnerability_sources(event, tags or []):
        for cve_id in normalize_cve_ids(source.get("value")):
            findings.append(
                compact_mapping(
                    {
                        "value": cve_id,
                        "source_field": source.get("source_field"),
                        "source_type": source.get("source_type"),
                        "attribute_type": source.get("attribute_type"),
                        "attribute_category": source.get("attribute_category"),
                        "attribute_uuid": source.get("attribute_uuid"),
                        "object_name": source.get("object_name"),
                        "object_uuid": source.get("object_uuid"),
                        "tags": source.get("tags"),
                    }
                )
            )
    return deduplicate_misp_vulnerabilities(findings)


def misp_vulnerability_sources(event, tags):
    event = compact_mapping(event)
    sources = []
    for index, tag in enumerate(tags or []):
        sources.append(
            {
                "value": tag,
                "source_field": f"tags[{index}]",
                "source_type": "tag",
            }
        )
    for field in ("info", "name", "description"):
        sources.append(
            {
                "value": event.get(field),
                "source_field": field,
                "source_type": "event",
            }
        )
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        if isinstance(attribute, Mapping):
            sources.append(
                misp_attribute_vulnerability_source(
                    attribute,
                    f"Attribute[{index}]",
                )
            )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        if not isinstance(misp_object, Mapping):
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            if isinstance(attribute, Mapping):
                sources.append(
                    misp_attribute_vulnerability_source(
                        attribute,
                        f"Object[{object_index}].Attribute[{attribute_index}]",
                        misp_object=misp_object,
                    )
                )
    return sources


def misp_attribute_vulnerability_source(attribute, source_field, misp_object=None):
    attribute = compact_mapping(attribute)
    misp_object = compact_mapping(misp_object)
    return compact_mapping(
        {
            "value": attribute.get("value"),
            "source_field": source_field,
            "source_type": "attribute",
            "attribute_type": attribute.get("type"),
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
        }
    )


def attribute_tags(attribute):
    tags = []
    for tag in list_values(attribute.get("Tag")):
        if isinstance(tag, Mapping):
            value = tag.get("name") or tag.get("Name")
        else:
            value = tag
        if value:
            tags.append(value)
    return tags


def normalize_cve_ids(value):
    cve_ids = []
    for item in flatten_text(value):
        for match in CVE_ID_PATTERN.findall(str(item or "")):
            normalized = match.upper()
            if normalized not in cve_ids:
                cve_ids.append(normalized)
    return cve_ids


def flatten_text(value):
    if value is None:
        return []
    if isinstance(value, Mapping):
        values = []
        for item in value.values():
            values.extend(flatten_text(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(flatten_text(item))
        return values
    return [value]


def deduplicate_misp_vulnerabilities(findings):
    seen = set()
    deduplicated = []
    for finding in findings:
        key = str(finding.get("value", "")).casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


def extract_misp_event_reports(event):
    event = compact_mapping(event)
    reports = []
    for index, report in enumerate(list_values(event.get("EventReport"))):
        normalized = normalize_misp_event_report(report, f"EventReport[{index}]")
        if normalized:
            reports.append(normalized)
    return deduplicate_misp_event_reports(reports)


def normalize_misp_event_report(report, source_field):
    report = compact_mapping(report)
    if not report or is_truthy(report.get("deleted")):
        return {}
    title = clean_text(
        report.get("name")
        or report.get("title")
        or report.get("event_report_title")
        or report.get("uuid")
    )
    content = clean_text(
        report.get("content")
        or report.get("text")
        or report.get("body")
        or report.get("value")
    )
    if not title and content:
        title = content[:120]
    if not title and not content:
        return {}
    return compact_mapping(
        {
            "title": title,
            "content": content,
            "uuid": report.get("uuid"),
            "timestamp": report.get("timestamp"),
            "created": report.get("created"),
            "modified": report.get("modified"),
            "source_field": source_field,
        }
    )


def deduplicate_misp_event_reports(reports):
    seen = set()
    deduplicated = []
    for report in reports:
        key = (
            str(report.get("uuid", "")).casefold(),
            str(report.get("title", "")).casefold(),
            str(report.get("content", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(report)
    return deduplicated


def extract_misp_sightings(event):
    event = compact_mapping(event)
    sightings = []
    for source in misp_sighting_sources(event):
        for index, sighting in enumerate(list_values(source.get("sightings"))):
            normalized = normalize_misp_sighting(
                sighting,
                source,
                f"{source.get('source_field')}.Sighting[{index}]",
            )
            if normalized:
                sightings.append(normalized)
    return deduplicate_misp_sightings(sightings)


def misp_sighting_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "sightings": attribute.get("Sighting"),
                "attribute_type": attribute.get("type"),
                "attribute_category": attribute.get("category"),
                "attribute_value": attribute.get("value"),
                "attribute_uuid": attribute.get("uuid"),
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "sightings": attribute.get("Sighting"),
                    "attribute_type": attribute.get("type"),
                    "attribute_category": attribute.get("category"),
                    "attribute_value": attribute.get("value"),
                    "attribute_uuid": attribute.get("uuid"),
                    "object_name": misp_object.get("name"),
                    "object_uuid": misp_object.get("uuid"),
                }
            )
    return sources


def normalize_misp_sighting(sighting, source, source_field):
    sighting = compact_mapping(sighting)
    source = compact_mapping(source)
    if not sighting or is_truthy(sighting.get("deleted")):
        return {}
    observed_value = clean_text(
        source.get("attribute_value")
        or sighting.get("value")
        or sighting.get("uuid")
        or sighting.get("id")
    )
    if not observed_value:
        return {}
    organization = compact_mapping(
        sighting.get("Organisation") or sighting.get("Organization")
    )
    return compact_mapping(
        {
            "value": observed_value,
            "sighting_id": sighting.get("id"),
            "sighting_uuid": sighting.get("uuid"),
            "sighting_type": sighting.get("type"),
            "date_sighting": sighting.get("date_sighting"),
            "source": sighting.get("source"),
            "organization": organization.get("name") or organization.get("uuid"),
            "organization_uuid": organization.get("uuid"),
            "attribute_type": source.get("attribute_type"),
            "attribute_category": source.get("attribute_category"),
            "attribute_uuid": source.get("attribute_uuid"),
            "object_name": source.get("object_name"),
            "object_uuid": source.get("object_uuid"),
            "source_field": source_field,
        }
    )


def deduplicate_misp_sightings(sightings):
    seen = set()
    deduplicated = []
    for sighting in sightings:
        key = (
            str(sighting.get("sighting_uuid", "")).casefold(),
            str(sighting.get("sighting_id", "")).casefold(),
            str(sighting.get("value", "")).casefold(),
            str(sighting.get("date_sighting", "")).casefold(),
            str(sighting.get("source", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(sighting)
    return deduplicated


def extract_misp_object_references(event):
    event = compact_mapping(event)
    references = []
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for reference_index, reference in enumerate(
            list_values(misp_object.get("ObjectReference"))
        ):
            normalized = normalize_misp_object_reference(
                reference,
                misp_object,
                f"Object[{object_index}].ObjectReference[{reference_index}]",
            )
            if normalized:
                references.append(normalized)
    return deduplicate_misp_object_references(references)


def normalize_misp_object_reference(reference, misp_object, source_field):
    reference = compact_mapping(reference)
    misp_object = compact_mapping(misp_object)
    if not reference or is_truthy(reference.get("deleted")):
        return {}
    source_uuid = clean_text(
        reference.get("object_uuid") or misp_object.get("uuid")
    )
    target_uuid = clean_text(
        reference.get("referenced_uuid")
        or reference.get("referenced_object_uuid")
        or reference.get("referenced_attribute_uuid")
    )
    relationship_type = normalize_misp_relationship_type(
        reference.get("relationship_type")
    )
    if not source_uuid or not target_uuid:
        return {}
    value = f"{source_uuid} {relationship_type} {target_uuid}"
    return compact_mapping(
        {
            "value": value,
            "relationship_type": relationship_type,
            "reference_id": reference.get("id"),
            "reference_uuid": reference.get("uuid"),
            "source_uuid": source_uuid,
            "source_name": misp_object.get("name"),
            "source_meta_category": misp_object.get("meta-category"),
            "target_uuid": target_uuid,
            "target_type": reference.get("referenced_type"),
            "comment": reference.get("comment"),
            "source_field": source_field,
        }
    )


def normalize_misp_relationship_type(value):
    normalized = clean_text(value).casefold().replace(" ", "-")
    return normalized or "related-to"


def deduplicate_misp_object_references(references):
    seen = set()
    deduplicated = []
    for reference in references:
        key = (
            str(reference.get("reference_uuid", "")).casefold(),
            str(reference.get("source_uuid", "")).casefold(),
            str(reference.get("relationship_type", "")).casefold(),
            str(reference.get("target_uuid", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(reference)
    return deduplicated


def extract_misp_detection_rules(event):
    event = compact_mapping(event)
    rules = []
    for source in misp_detection_rule_sources(event):
        normalized = normalize_misp_detection_rule(source)
        if normalized:
            rules.append(normalized)
    return deduplicate_misp_detection_rules(rules)


def misp_detection_rule_sources(event):
    event = compact_mapping(event)
    sources = []
    for index, attribute in enumerate(list_values(event.get("Attribute"))):
        attribute = compact_mapping(attribute)
        if not attribute:
            continue
        sources.append(
            {
                "source_field": f"Attribute[{index}]",
                "attribute": attribute,
                "object": {},
            }
        )
    for object_index, misp_object in enumerate(list_values(event.get("Object"))):
        misp_object = compact_mapping(misp_object)
        if not misp_object:
            continue
        for attribute_index, attribute in enumerate(
            list_values(misp_object.get("Attribute"))
        ):
            attribute = compact_mapping(attribute)
            if not attribute:
                continue
            sources.append(
                {
                    "source_field": (
                        f"Object[{object_index}].Attribute[{attribute_index}]"
                    ),
                    "attribute": attribute,
                    "object": misp_object,
                }
            )
    return sources


def normalize_misp_detection_rule(source):
    source = compact_mapping(source)
    attribute = compact_mapping(source.get("attribute"))
    misp_object = compact_mapping(source.get("object"))
    rule_type = clean_text(attribute.get("type")).casefold()
    rule_content = clean_text(attribute.get("value"))
    if rule_type not in DETECTION_RULE_TYPES:
        return {}
    if not rule_content or is_truthy(attribute.get("deleted")):
        return {}
    title = clean_text(
        attribute.get("comment")
        or attribute.get("uuid")
        or f"{rule_type} detection rule"
    )
    return compact_mapping(
        {
            "value": title,
            "rule_type": rule_type,
            "pattern_type": rule_type,
            "pattern": rule_content,
            "attribute_category": attribute.get("category"),
            "attribute_uuid": attribute.get("uuid"),
            "object_name": misp_object.get("name"),
            "object_uuid": misp_object.get("uuid"),
            "tags": [tag_name for tag_name in attribute_tags(attribute) if tag_name],
            "source_field": source.get("source_field"),
        }
    )


def deduplicate_misp_detection_rules(rules):
    seen = set()
    deduplicated = []
    for rule in rules:
        key = (
            str(rule.get("attribute_uuid", "")).casefold(),
            str(rule.get("rule_type", "")).casefold(),
            str(rule.get("pattern", "")).casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(rule)
    return deduplicated


def clean_text(value):
    return " ".join(str(value or "").strip().split())


def is_truthy(value):
    if value is True:
        return True
    return clean_text(value).casefold() in {"1", "true", "yes"}


class MISPProcessor:
    def __init__(
        self,
        settings,
        misp_client,
        api_client,
        logger,
        exporter=send_bundle,
        state_repository_factory=MISPEventStateRepository,
        sleeper=time.sleep,
        ingest_pause_seconds=2,
        feed_adapter=None,
        decision_audit=None,
        artifact_dedup=None,
        quarantine_repository=None,
        graph_deduplication_index=None,
    ):
        self.settings = settings
        self.misp_client = misp_client
        self.feed_adapter = feed_adapter or MISPFeedAdapter(
            misp_client,
            limits=settings.adapter_limits,
            logger=logger,
        )
        self.api_client = api_client
        self.log = logger
        self.exporter = exporter
        self.state_repository_factory = state_repository_factory
        self.sleeper = sleeper
        self.ingest_pause_seconds = ingest_pause_seconds
        self.decision_audit = decision_audit or DecisionAuditLog()
        self.artifact_dedup = artifact_dedup
        self.quarantine_repository = quarantine_repository or self.build_quarantine_repository(
            settings
        )
        self.graph_deduplication_index = (
            graph_deduplication_index or self.build_graph_deduplication_index(settings)
        )
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_event,
            max_days_hard_filter=settings.max_days_hard_filter,
        )
        self.graph_candidate_policy = graph_candidate_policy_from_settings(settings)

    def build_quarantine_repository(self, settings):
        repository_file = getattr(settings, "quarantine_repository_file", "")
        if not repository_file:
            return None
        return QuarantineRepository(repository_file)

    def build_graph_deduplication_index(self, settings):
        state_file = getattr(settings, "graph_dedup_state_file", "")
        if not state_file:
            return None
        return GraphDeduplicationIndex(state_file)

    def run_once(self):
        state = self.state_repository_factory(self.settings.state_file)
        summaries = []

        for query in self.settings.misp_queries:
            summaries.append(self.process_query(query, state))

        return summaries

    def process_query(self, query, state):
        self.log(f"MISP query: {query}")
        candidates = self.feed_adapter.search(query)
        adapter_available = getattr(self.feed_adapter, "last_search_available", len(candidates))
        adapter_skipped = getattr(self.feed_adapter, "last_search_skipped", 0)
        outcomes = {
            "ingest": 0,
            "drop": 0,
            "quarantine": 0,
            "skip": 0,
            "error": 0,
            "dry_run": 0,
        }
        reviewed = 0

        for candidate in candidates[: self.settings.max_events_per_run]:
            reviewed += 1
            action = self.process_event_outcome(query, candidate, state)
            if action in outcomes:
                outcomes[action] += 1

            if action == "ingest":
                self.sleeper(self.ingest_pause_seconds)

        summary = FeedRunSummary(
            source=self.feed_adapter.source,
            query=query,
            reviewed=reviewed,
            ingested=outcomes["ingest"],
            available=adapter_available,
            dropped=outcomes["drop"],
            quarantined=outcomes["quarantine"],
            skipped=outcomes["skip"] + adapter_skipped,
            errors=outcomes["error"],
            dry_run=outcomes["dry_run"],
        )
        self.log(
            f"MISP query summary: {summary.query} reviewed={summary.reviewed} "
            f"ingested={summary.ingested} dropped={summary.dropped} "
            f"quarantined={summary.quarantined} skipped={summary.skipped} "
            f"errors={summary.errors} dry_run={summary.dry_run} "
            f"available={summary.available}"
        )
        return summary

    def process_event(self, query, event, state):
        return self.process_event_outcome(query, event, state) == "ingest"

    def process_event_outcome(self, query, event, state):
        candidate_ref = self.normalize_feed_candidate(event)
        event_id = candidate_ref.external_id

        if not event_id:
            self.log(f"Skip MISP event without id: {candidate_ref.title}")
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="missing external id",
            )
            return "skip"

        if state.has_event(event_id):
            self.log(f"Skip MISP state: {candidate_ref.title}")
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="already processed",
            )
            return "skip"

        candidate = self.enrich_candidate(query, candidate_ref)
        if not candidate:
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="enrichment failed",
            )
            return "skip"

        action, reason = self.candidate_tlp_decision(candidate)
        if action != "ingest":
            self.record_decision(query, candidate_ref, action, reason, candidate)
            return action

        action, reason = self.candidate_policy_decision(candidate)
        if action != "ingest":
            self.record_decision(query, candidate_ref, action, reason, candidate)
            return action

        candidate = self.apply_indicator_type_filter(query, candidate_ref, candidate)
        if not candidate:
            return "skip"

        candidate = self.apply_artifact_dedup(query, candidate_ref, candidate)
        if not candidate:
            return "skip"

        if self.settings.dry_run:
            self.log(
                f"MISP dry-run: {candidate.name} score={candidate.score} "
                f"reason={reason}"
            )
            self.record_decision(
                query,
                candidate_ref,
                action="dry_run",
                reason=reason,
                candidate=candidate,
            )
            return "dry_run"

        if not self.ingest_candidate(candidate, reason):
            self.record_decision(
                query,
                candidate_ref,
                action="error",
                reason="export failed",
                candidate=candidate,
            )
            return "error"

        self.mark_artifacts(candidate_ref, candidate)
        state.mark_event(event_id)
        self.record_decision(query, candidate_ref, "ingest", reason, candidate)
        return "ingest"

    def normalize_feed_candidate(self, event):
        if hasattr(event, "external_id") and hasattr(event, "raw"):
            return event
        return event_to_feed_candidate(event)

    def enrich_candidate(self, query, candidate_ref):
        enriched = self.feed_adapter.enrich(candidate_ref)
        if not enriched:
            self.log(f"Skip MISP enrich failed: {candidate_ref.title}")
            return None

        candidate = self.prepare_candidate(query, enriched.raw)
        self.log(
            f"MISP candidate: {candidate.name} age={age_label(candidate.age)} "
            f"iocs={candidate.ioc_count} score={candidate.score}"
        )
        return candidate

    def evaluate_candidate_policy(self, candidate):
        action, reason = self.candidate_policy_decision(candidate)
        return action == "ingest", reason

    def candidate_policy_decision(self, candidate):
        decision, reason = should_ingest(
            candidate.event,
            candidate.score,
            self.policy_config,
        )

        if decision == "quarantine":
            self.log(
                f"MISP quarantine: {candidate.name} "
                f"score={candidate.score} reason={reason}"
            )
            return "quarantine", reason

        if decision is False:
            self.log(
                f"MISP drop: {candidate.name} score={candidate.score} reason={reason}"
            )
            return "drop", reason

        return "ingest", reason

    def candidate_tlp_decision(self, candidate):
        allowed, reason = tlp_is_allowed(
            candidate.event.get("tags", []),
            getattr(self.settings, "allowed_tlp", []),
        )
        if not allowed:
            self.log(f"MISP drop: {candidate.name} reason={reason}")
            return "drop", reason
        return "ingest", "ok"

    def record_decision(self, query, candidate_ref, action, reason, candidate=None):
        title = candidate.name if candidate and candidate.name else candidate_ref.title
        indicator_count = candidate.ioc_count if candidate else 0
        score = candidate.score if candidate else None
        candidate_age = candidate.age if candidate else None

        decision = DecisionRecord(
            action=action,
            reason=reason,
            source_key=candidate_ref.source.key,
            external_id=candidate_ref.external_id,
            title=title,
            query=query,
            score=score,
            age_days=candidate_age,
            indicator_count=indicator_count,
            metadata=decision_metadata(
                candidate_ref,
                candidate,
                graph_candidate_policy=self.graph_candidate_policy,
                graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
                graph_deduplication_index=self.graph_deduplication_index,
            ),
        )

        try:
            self.decision_audit.record(decision)
        except Exception as exc:
            self.log(f"MISP decision audit failed: {title} error={exc}")

        if action == "quarantine":
            self.record_quarantine(query, candidate_ref, reason, candidate)

    def record_quarantine(self, query, candidate_ref, reason, candidate=None):
        if not self.quarantine_repository:
            return

        title = candidate.name if candidate and candidate.name else candidate_ref.title
        indicators = list(candidate.indicators if candidate else candidate_ref.indicators)
        raw_source = candidate.event if candidate else candidate_ref.raw
        raw_snapshot, truncated = bounded_raw_snapshot(
            raw_source,
            getattr(self.settings, "quarantine_raw_snapshot_max_bytes", 65536),
        )
        metadata = decision_metadata(
            candidate_ref,
            candidate,
            graph_candidate_policy=self.graph_candidate_policy,
            graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
            graph_deduplication_index=self.graph_deduplication_index,
        )
        if truncated:
            metadata["raw_snapshot_truncated"] = True

        record = QuarantineRecord(
            source_key=candidate_ref.source.key,
            external_id=candidate_ref.external_id,
            title=title,
            reason=reason,
            query=query,
            score=candidate.score if candidate else None,
            age_days=candidate.age if candidate else None,
            indicator_count=candidate.ioc_count if candidate else len(indicators),
            indicators=indicators,
            metadata=metadata,
            raw_snapshot=raw_snapshot,
        )

        try:
            queued = self.quarantine_repository.add(record)
            self.log(
                f"MISP quarantine queued: {title} "
                f"id={queued.get('quarantine_id')} status={queued.get('status')}"
            )
        except Exception as exc:
            self.log(f"MISP quarantine repository failed: {title} error={exc}")

    def apply_artifact_dedup(self, query, candidate_ref, candidate):
        if not self.artifact_dedup:
            return candidate

        indicators, duplicate_count = self.artifact_dedup.filter_new_indicators(
            candidate.indicators
        )
        if duplicate_count:
            self.log(
                f"MISP artifact dedup: {candidate.name} duplicates={duplicate_count}"
            )
        if not indicators:
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="all indicators already known",
                candidate=candidate,
            )
            return None
        if len(indicators) == len(candidate.indicators):
            return candidate
        return MISPEventCandidate(
            event=candidate.event,
            name=candidate.name,
            description=candidate.description,
            indicators=indicators,
            ioc_count=len(indicators),
            age=candidate.age,
            score=candidate.score,
            score_details=candidate.score_details,
        )

    def apply_indicator_type_filter(self, query, candidate_ref, candidate):
        indicators, dropped_count = filter_indicators_by_type(
            candidate.indicators,
            getattr(self.settings, "allowed_indicator_types", []),
        )
        if not dropped_count:
            return candidate
        self.log(
            f"MISP indicator type filter: {candidate.name} "
            f"dropped={dropped_count} kept={len(indicators)}"
        )
        if not indicators:
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="all indicators disallowed by type",
                candidate=candidate,
            )
            return None
        return MISPEventCandidate(
            event=candidate.event,
            name=candidate.name,
            description=candidate.description,
            indicators=indicators,
            ioc_count=len(indicators),
            age=candidate.age,
            score=candidate.score,
            score_details=candidate.score_details,
        )

    def mark_artifacts(self, candidate_ref, candidate):
        if not self.artifact_dedup:
            return
        try:
            added = self.artifact_dedup.mark_indicators(
                candidate.indicators,
                source_key=candidate_ref.source.key,
                external_id=candidate_ref.external_id,
                title=candidate.name or candidate_ref.title,
            )
        except Exception as exc:
            self.log(f"MISP artifact dedup mark failed: {candidate.name} error={exc}")
            return
        if added:
            self.log(f"MISP artifact dedup mark: {candidate.name} added={added}")

    def ingest_candidate(self, candidate, reason):
        self.log(f"MISP ingest: {candidate.name} score={candidate.score} reason={reason}")
        try:
            imported_iocs = self.exporter(
                self.api_client,
                candidate.name,
                candidate.description,
                candidate.score,
                candidate.indicators,
                identity_name=self.settings.connector_name,
            )
        except Exception as exc:
            self.log(f"MISP ingest failed: {candidate.name} error={exc}")
            return False

        self.log(f"MISP ingest complete: {candidate.name} indicators={imported_iocs}")
        return True

    def apply_ioc_guardrail(self, event, indicators):
        ioc_count = len(indicators)
        exported_ioc_count = min(ioc_count, self.settings.max_iocs_per_event)
        controls = compact_mapping(event.get("narrowcti_controls"))
        controls.update(
            {
                "indicator_count": ioc_count,
                "max_iocs_per_event": self.settings.max_iocs_per_event,
                "exported_indicator_count": exported_ioc_count,
                "iocs_truncated": ioc_count > self.settings.max_iocs_per_event,
            }
        )
        event["narrowcti_controls"] = controls

        if controls["iocs_truncated"]:
            self.log(
                "MISP event exceeds IOC guardrail: "
                f"event={event.get('id') or event.get('uuid')} "
                f"iocs={ioc_count} "
                f"limit={self.settings.max_iocs_per_event} "
                "action=truncate"
            )
            return indicators[: self.settings.max_iocs_per_event], ioc_count

        return indicators, ioc_count

    def prepare_candidate(self, query, event):
        indicators, ioc_count = self.apply_ioc_guardrail(
            event,
            list(event.get("indicators", [])),
        )
        score_details = calculate_score_details(
            event,
            query,
            source_confidence=getattr(self.settings, "source_confidence", 50),
        )

        return MISPEventCandidate(
            event=event,
            name=event.get("name"),
            description=event.get("description", ""),
            indicators=indicators,
            ioc_count=ioc_count,
            age=age_days(event.get("created")),
            score=score_details["final_score"],
            score_details=score_details,
        )


def graph_candidate_policy_from_settings(settings):
    return {
        "min_entity_confidence": getattr(settings, "graph_min_entity_confidence", 0),
        "min_relationship_confidence": getattr(
            settings,
            "graph_min_relationship_confidence",
            0,
        ),
        "allowed_entity_types": getattr(settings, "graph_allowed_entity_types", []),
        "allowed_stix_object_types": getattr(
            settings,
            "graph_allowed_stix_object_types",
            [],
        ),
        "require_relationship_provenance": getattr(
            settings,
            "graph_require_relationship_provenance",
            False,
        ),
    }
