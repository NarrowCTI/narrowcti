import time

from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.graph_candidates import apply_graph_candidate_policy, build_graph_candidates
from core.graph_evidence import build_graph_evidence
from core.graph_export_plan import build_graph_export_plan
from core.indicator_policy import filter_indicators_by_type
from core.mitre_attack import MITREAttackResolver
from core.policy import PolicyConfig, should_ingest
from core.quarantine import (
    QuarantineRecord,
    QuarantineRepository,
    bounded_raw_snapshot,
)
from core.scoring import age_days, calculate_score_details
from core.state_repository import PulseStateRepository
from core.tlp import tlp_is_allowed
from exporters.opencti import send_bundle

try:
    from .entity_extraction import extract_otx_entities
    from .feed_adapter import OTXFeedAdapter, pulse_to_feed_candidate
    from .models import PulseCandidate, QuerySummary
except ImportError:
    from entity_extraction import extract_otx_entities
    from feed_adapter import OTXFeedAdapter, pulse_to_feed_candidate
    from models import PulseCandidate, QuerySummary


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


def decision_metadata(
    candidate=None,
    enable_entity_extraction=True,
    mitre_resolver=None,
    source_key="",
    external_id="",
    title="",
    graph_candidate_policy=None,
    graph_export_mode="audit",
):
    score_details = getattr(candidate, "score_details", None)
    if not candidate:
        return {}
    metadata = {}
    if score_details:
        metadata["scoring"] = dict(score_details)
    if enable_entity_extraction:
        metadata["otx_entities"] = extract_otx_entities(candidate.pulse)
        enrich_mitre_attack_metadata(metadata, mitre_resolver)
    metadata["graph_evidence"] = build_graph_evidence(
        metadata,
        source_key=source_key,
        external_id=external_id or candidate.pulse.get("id", ""),
        title=title or candidate.name,
    )
    graph_candidates = build_graph_candidates(metadata["graph_evidence"])
    metadata["graph_candidates"] = graph_candidates.to_dict()
    graph_policy = apply_graph_candidate_policy(
        graph_candidates,
        **(graph_candidate_policy or {}),
    ).to_dict()
    metadata["graph_candidate_policy"] = graph_policy
    metadata["graph_export_plan"] = build_graph_export_plan(
        graph_policy,
        mode=graph_export_mode,
    )
    return metadata


def enrich_mitre_attack_metadata(metadata, mitre_resolver=None):
    attack_ids = (metadata.get("otx_entities") or {}).get("attack_ids") or []
    if not attack_ids:
        return metadata
    if not mitre_resolver:
        metadata["mitre_attack"] = {
            "available": False,
            "reason": "mitre cache unavailable",
            "resolved": [],
        }
        return metadata
    metadata["mitre_attack"] = {
        "available": True,
        "resolved": mitre_resolver.resolve(attack_ids),
    }
    return metadata


class OTXProcessor:
    def __init__(
        self,
        settings,
        otx_client,
        api_client,
        logger,
        exporter=send_bundle,
        state_repository_factory=PulseStateRepository,
        sleeper=time.sleep,
        ingest_pause_seconds=2,
        feed_adapter=None,
        decision_audit=None,
        artifact_dedup=None,
        quarantine_repository=None,
        mitre_resolver=None,
    ):
        self.settings = settings
        self.otx_client = otx_client
        self.feed_adapter = feed_adapter or OTXFeedAdapter(otx_client)
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
        self.mitre_resolver = mitre_resolver or self.build_mitre_resolver(settings)
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_pulse,
            max_days_hard_filter=settings.max_days_hard_filter,
        )
        self.graph_candidate_policy = graph_candidate_policy_from_settings(settings)

    def build_quarantine_repository(self, settings):
        repository_file = getattr(settings, "quarantine_repository_file", "")
        if not repository_file:
            return None
        return QuarantineRepository(repository_file)

    def build_mitre_resolver(self, settings):
        if not getattr(settings, "enable_mitre_attack_resolution", True):
            return None
        cache_file = getattr(settings, "mitre_cache_file", "")
        if not cache_file:
            return None
        try:
            return MITREAttackResolver(cache_file=cache_file)
        except Exception as exc:
            self.log(f"MITRE ATT&CK cache unavailable: {cache_file} error={exc}")
            return None

    def run_once(self):
        state = self.state_repository_factory(self.settings.state_file)
        summaries = []

        for query in self.settings.otx_queries:
            summaries.append(self.process_query(query, state))

        return summaries

    def process_query(self, query, state):
        self.log(f"Query: {query}")
        candidates = self.feed_adapter.search(query)
        outcomes = {
            "ingest": 0,
            "drop": 0,
            "quarantine": 0,
            "skip": 0,
            "error": 0,
            "dry_run": 0,
        }
        ingested = 0
        reviewed = 0

        for candidate in candidates[: self.settings.max_search_results_per_query]:
            if ingested >= self.settings.max_pulses_per_query:
                break

            reviewed += 1
            action = self.process_pulse_outcome(query, candidate, state)
            if action in outcomes:
                outcomes[action] += 1

            if action == "ingest":
                ingested += 1
                self.sleeper(self.ingest_pause_seconds)

        summary = QuerySummary(
            query=query,
            reviewed=reviewed,
            ingested=ingested,
            available=len(candidates),
            dropped=outcomes["drop"],
            quarantined=outcomes["quarantine"],
            skipped=outcomes["skip"],
            errors=outcomes["error"],
            dry_run=outcomes["dry_run"],
        )
        self.log(
            f"Query summary: {summary.query} reviewed={summary.reviewed} "
            f"ingested={summary.ingested} dropped={summary.dropped} "
            f"quarantined={summary.quarantined} skipped={summary.skipped} "
            f"errors={summary.errors} dry_run={summary.dry_run} "
            f"available={summary.available}"
        )
        return summary

    def process_pulse(self, query, pulse, state):
        return self.process_pulse_outcome(query, pulse, state) == "ingest"

    def process_pulse_outcome(self, query, pulse, state):
        candidate_ref = self.normalize_feed_candidate(pulse)
        pulse_id = candidate_ref.external_id

        if not pulse_id:
            self.log(f"Skip pulse without id: {candidate_ref.title}")
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="missing external id",
            )
            return "skip"

        if state.has_pulse(pulse_id):
            self.log(f"Skip state: {candidate_ref.title}")
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

        if getattr(self.settings, "dry_run", False):
            self.log(
                f"Dry-run: {candidate.name} score={candidate.score} "
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
        state.mark_pulse(pulse_id)
        self.record_decision(query, candidate_ref, "ingest", reason, candidate)
        return "ingest"

    def normalize_feed_candidate(self, pulse):
        if hasattr(pulse, "external_id") and hasattr(pulse, "raw"):
            return pulse
        return pulse_to_feed_candidate(pulse)

    def enrich_candidate(self, query, candidate_ref):
        enriched = self.feed_adapter.enrich(candidate_ref)
        if not enriched:
            self.log(f"Skip enrich failed: {candidate_ref.title}")
            return None

        candidate = self.prepare_candidate(query, enriched.raw)
        self.log(
            f"Candidate: {candidate.name} age={age_label(candidate.age)} "
            f"iocs={candidate.ioc_count} score={candidate.score}"
        )
        return candidate

    def evaluate_candidate_policy(self, candidate):
        action, reason = self.candidate_policy_decision(candidate)
        return action == "ingest", reason

    def candidate_policy_decision(self, candidate):
        decision, reason = should_ingest(
            candidate.pulse,
            candidate.score,
            self.policy_config,
        )

        if decision == "quarantine":
            self.log(
                f"Quarantine: {candidate.name} "
                f"score={candidate.score} reason={reason}"
            )
            return "quarantine", reason

        if decision is False:
            self.log(f"Drop: {candidate.name} score={candidate.score} reason={reason}")
            return "drop", reason

        return "ingest", reason

    def candidate_tlp_decision(self, candidate):
        allowed, reason = tlp_is_allowed(
            candidate.pulse.get("tags", []),
            getattr(self.settings, "allowed_tlp", []),
        )
        if not allowed:
            self.log(f"Drop: {candidate.name} reason={reason}")
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
                candidate,
                getattr(self.settings, "enable_otx_entity_extraction", True),
                self.mitre_resolver,
                source_key=candidate_ref.source.key,
                external_id=candidate_ref.external_id,
                title=title,
                graph_candidate_policy=self.graph_candidate_policy,
                graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
            ),
        )

        try:
            self.decision_audit.record(decision)
        except Exception as exc:
            self.log(f"Decision audit failed: {title} error={exc}")

        if action == "quarantine":
            self.record_quarantine(query, candidate_ref, reason, candidate)

    def record_quarantine(self, query, candidate_ref, reason, candidate=None):
        if not self.quarantine_repository:
            return

        title = candidate.name if candidate and candidate.name else candidate_ref.title
        indicators = list(candidate.indicators if candidate else candidate_ref.indicators)
        raw_source = candidate.pulse if candidate else candidate_ref.raw
        raw_snapshot, truncated = bounded_raw_snapshot(
            raw_source,
            getattr(self.settings, "quarantine_raw_snapshot_max_bytes", 65536),
        )
        metadata = decision_metadata(
            candidate,
            getattr(self.settings, "enable_otx_entity_extraction", True),
            self.mitre_resolver,
            source_key=candidate_ref.source.key,
            external_id=candidate_ref.external_id,
            title=title,
            graph_candidate_policy=self.graph_candidate_policy,
            graph_export_mode=getattr(self.settings, "graph_export_mode", "audit"),
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
                f"Quarantine queued: {title} "
                f"id={queued.get('quarantine_id')} status={queued.get('status')}"
            )
        except Exception as exc:
            self.log(f"Quarantine repository failed: {title} error={exc}")

    def apply_artifact_dedup(self, query, candidate_ref, candidate):
        if not self.artifact_dedup:
            return candidate

        indicators, duplicate_count = self.artifact_dedup.filter_new_indicators(
            candidate.indicators
        )
        if duplicate_count:
            self.log(
                f"Artifact dedup: {candidate.name} duplicates={duplicate_count}"
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
        return PulseCandidate(
            pulse=candidate.pulse,
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
            f"Indicator type filter: {candidate.name} dropped={dropped_count} "
            f"kept={len(indicators)}"
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
        return PulseCandidate(
            pulse=candidate.pulse,
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
            self.log(f"Artifact dedup mark failed: {candidate.name} error={exc}")
            return
        if added:
            self.log(f"Artifact dedup mark: {candidate.name} added={added}")

    def ingest_candidate(self, candidate, reason):
        self.log(f"Ingest: {candidate.name} score={candidate.score} reason={reason}")
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
            self.log(f"Ingest failed: {candidate.name} error={exc}")
            return False

        self.log(f"Ingest complete: {candidate.name} indicators={imported_iocs}")
        return True

    def prepare_candidate(self, query, pulse):
        indicators = pulse.get("indicators", [])
        ioc_count = len(indicators)
        score_details = calculate_score_details(
            pulse,
            query,
            source_confidence=getattr(self.settings, "source_confidence", 50),
        )

        if ioc_count > self.settings.max_iocs_per_pulse:
            indicators = indicators[: self.settings.max_iocs_per_pulse]

        return PulseCandidate(
            pulse=pulse,
            name=pulse.get("name"),
            description=pulse.get("description", ""),
            indicators=indicators,
            ioc_count=ioc_count,
            age=age_days(pulse.get("created")),
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
