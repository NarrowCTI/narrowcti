import time
from collections.abc import Mapping

from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.feed_contract import FeedRunSummary
from core.policy import PolicyConfig, should_ingest
from core.scoring import age_days, calculate_score
from core.state_repository import MISPEventStateRepository
from exporters.opencti import send_bundle

from connectors.misp.feed_adapter import MISPFeedAdapter, event_to_feed_candidate
from connectors.misp.models import MISPEventCandidate


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


def compact_mapping(value):
    return dict(value) if isinstance(value, Mapping) else {}


def decision_metadata(candidate_ref, candidate=None):
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
    if controls:
        metadata["guardrails"] = controls
    return metadata


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
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_event,
            max_days_hard_filter=settings.max_days_hard_filter,
        )

    def run_once(self):
        state = self.state_repository_factory(self.settings.state_file)
        summaries = []

        for query in self.settings.misp_queries:
            summaries.append(self.process_query(query, state))

        return summaries

    def process_query(self, query, state):
        self.log(f"MISP query: {query}")
        candidates = self.feed_adapter.search(query)
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
            available=len(candidates),
            dropped=outcomes["drop"],
            quarantined=outcomes["quarantine"],
            skipped=outcomes["skip"],
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

        action, reason = self.candidate_policy_decision(candidate)
        if action != "ingest":
            self.record_decision(query, candidate_ref, action, reason, candidate)
            return action

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
            metadata=decision_metadata(candidate_ref, candidate),
        )

        try:
            self.decision_audit.record(decision)
        except Exception as exc:
            self.log(f"MISP decision audit failed: {title} error={exc}")

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

    def prepare_candidate(self, query, event):
        indicators = list(event.get("indicators", []))
        ioc_count = len(indicators)

        if ioc_count > self.settings.max_iocs_per_event:
            indicators = indicators[: self.settings.max_iocs_per_event]

        return MISPEventCandidate(
            event=event,
            name=event.get("name"),
            description=event.get("description", ""),
            indicators=indicators,
            ioc_count=ioc_count,
            age=age_days(event.get("created")),
            score=calculate_score(event, query),
        )
