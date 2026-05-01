import time

from core.policy import PolicyConfig, should_ingest
from core.scoring import age_days, calculate_score
from core.state_repository import PulseStateRepository
from exporters.opencti import send_bundle

try:
    from .models import PulseCandidate, QuerySummary
except ImportError:
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
    ):
        self.settings = settings
        self.otx_client = otx_client
        self.api_client = api_client
        self.log = logger
        self.exporter = exporter
        self.state_repository_factory = state_repository_factory
        self.sleeper = sleeper
        self.ingest_pause_seconds = ingest_pause_seconds
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
        pulses = self.otx_client.search_pulses(query)
        ingested = 0
        reviewed = 0

        for pulse in pulses[: self.settings.max_search_results_per_query]:
            if ingested >= self.settings.max_pulses_per_query:
                break

            reviewed += 1
            if self.process_pulse(query, pulse, state):
                ingested += 1
                self.sleeper(self.ingest_pause_seconds)

        summary = QuerySummary(
            query=query,
            reviewed=reviewed,
            ingested=ingested,
            available=len(pulses),
        )
        self.log(
            f"Query summary: {summary.query} reviewed={summary.reviewed} "
            f"ingested={summary.ingested} available={summary.available}"
        )
        return summary

    def process_pulse(self, query, pulse, state):
        pulse_id = pulse.get("id")

        if not pulse_id:
            self.log(f"Skip pulse without id: {pulse.get('name')}")
            return False

        if state.has_pulse(pulse_id):
            self.log(f"Skip state: {pulse.get('name')}")
            return False

        candidate = self.enrich_candidate(query, pulse)
        if not candidate:
            return False

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
            return False

        if decision is False:
            self.log(f"Drop: {candidate.name} score={candidate.score} reason={reason}")
            return False

        if not self.ingest_candidate(candidate, reason):
            return False

        state.mark_pulse(pulse_id)
        return True

    def enrich_candidate(self, query, pulse):
        full = self.otx_client.enrich_pulse(pulse["id"])
        if not full:
            self.log(f"Skip enrich failed: {pulse.get('name')}")
            return None

        candidate = self.prepare_candidate(query, full)
        self.log(
            f"Candidate: {candidate.name} age={age_label(candidate.age)} "
            f"iocs={candidate.ioc_count} score={candidate.score}"
        )
        return candidate

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
