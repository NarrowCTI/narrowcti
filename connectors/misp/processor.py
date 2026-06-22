import time
from collections.abc import Mapping

from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.feed_contract import FeedRunSummary
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
    score_details = getattr(candidate, "score_details", None)
    if score_details:
        metadata["scoring"] = dict(score_details)
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
        artifact_dedup=None,
        quarantine_repository=None,
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
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_event,
            max_days_hard_filter=settings.max_days_hard_filter,
        )

    def build_quarantine_repository(self, settings):
        repository_file = getattr(settings, "quarantine_repository_file", "")
        if not repository_file:
            return None
        return QuarantineRepository(repository_file)

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
            metadata=decision_metadata(candidate_ref, candidate),
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
        metadata = decision_metadata(candidate_ref, candidate)
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
