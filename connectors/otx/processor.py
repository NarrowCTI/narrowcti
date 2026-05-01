import time

from core.decision_audit import DecisionAuditLog, DecisionRecord
from core.policy import PolicyConfig, should_ingest
from core.scoring import age_days, calculate_score
from core.state_repository import PulseStateRepository
from exporters.opencti import send_bundle

try:
    from .feed_adapter import OTXFeedAdapter, pulse_to_feed_candidate
    from .models import PulseCandidate, QuerySummary
except ImportError:
    from feed_adapter import OTXFeedAdapter, pulse_to_feed_candidate
    from models import PulseCandidate, QuerySummary


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


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
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_pulse,
            max_days_hard_filter=settings.max_days_hard_filter,
        )

    def run_once(self):
        state = self.state_repository_factory(self.settings.state_file)
        summaries = []

        for query in self.settings.otx_queries:
            summaries.append(self.process_query(query, state))

        return summaries

    def process_query(self, query, state):
        self.log(f"Query: {query}")
        candidates = self.feed_adapter.search(query)
        ingested = 0
        reviewed = 0

        for candidate in candidates[: self.settings.max_search_results_per_query]:
            if ingested >= self.settings.max_pulses_per_query:
                break

            reviewed += 1
            if self.process_pulse(query, candidate, state):
                ingested += 1
                self.sleeper(self.ingest_pause_seconds)

        summary = QuerySummary(
            query=query,
            reviewed=reviewed,
            ingested=ingested,
            available=len(candidates),
        )
        self.log(
            f"Query summary: {summary.query} reviewed={summary.reviewed} "
            f"ingested={summary.ingested} available={summary.available}"
        )
        return summary

    def process_pulse(self, query, pulse, state):
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
            return False

        if state.has_pulse(pulse_id):
            self.log(f"Skip state: {candidate_ref.title}")
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="already processed",
            )
            return False

        candidate = self.enrich_candidate(query, candidate_ref)
        if not candidate:
            self.record_decision(
                query,
                candidate_ref,
                action="skip",
                reason="enrichment failed",
            )
            return False

        action, reason = self.candidate_policy_decision(candidate)
        if action != "ingest":
            self.record_decision(query, candidate_ref, action, reason, candidate)
            return False

        if not self.ingest_candidate(candidate, reason):
            self.record_decision(
                query,
                candidate_ref,
                action="error",
                reason="export failed",
                candidate=candidate,
            )
            return False

        state.mark_pulse(pulse_id)
        self.record_decision(query, candidate_ref, "ingest", reason, candidate)
        return True

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
        )

        try:
            self.decision_audit.record(decision)
        except Exception as exc:
            self.log(f"Decision audit failed: {title} error={exc}")

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

        if ioc_count > self.settings.max_iocs_per_pulse:
            indicators = indicators[: self.settings.max_iocs_per_pulse]

        return PulseCandidate(
            pulse=pulse,
            name=pulse.get("name"),
            description=pulse.get("description", ""),
            indicators=indicators,
            ioc_count=ioc_count,
            age=age_days(pulse.get("created")),
            score=calculate_score(pulse, query),
        )
