import time
from dataclasses import dataclass

from core.policy import PolicyConfig, should_ingest
from core.scoring import age_days, calculate_score
from core.state_repository import PulseStateRepository
from exporters.opencti import send_bundle


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


@dataclass(frozen=True)
class PulseCandidate:
    pulse: dict
    name: str
    description: str
    indicators: list[dict]
    ioc_count: int
    age: int | None
    score: int


class OTXProcessor:
    def __init__(self, settings, otx_client, api_client, logger):
        self.settings = settings
        self.otx_client = otx_client
        self.api_client = api_client
        self.log = logger
        self.policy_config = PolicyConfig(
            quarantine_score_threshold=settings.quarantine_score_threshold,
            enable_quarantine=settings.enable_quarantine,
            min_score_to_ingest=settings.min_score_to_ingest,
            max_days_old=settings.max_days_old,
            min_score_for_old_pulse=settings.min_score_for_old_pulse,
            max_days_hard_filter=settings.max_days_hard_filter,
        )

    def run_once(self):
        state = PulseStateRepository(self.settings.state_file)

        for query in self.settings.otx_queries:
            self.process_query(query, state)

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
                time.sleep(2)

        self.log(
            f"Query summary: {query} reviewed={reviewed} "
            f"ingested={ingested} available={len(pulses)}"
        )

    def process_pulse(self, query, pulse, state):
        pulse_id = pulse.get("id")

        if state.has_pulse(pulse_id):
            self.log(f"Skip state: {pulse.get('name')}")
            return False

        full = self.otx_client.enrich_pulse(pulse_id)
        if not full:
            self.log(f"Skip enrich failed: {pulse.get('name')}")
            return False

        candidate = self.prepare_candidate(query, full)
        self.log(
            f"Candidate: {candidate.name} age={age_label(candidate.age)} "
            f"iocs={candidate.ioc_count} score={candidate.score}"
        )

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

        self.log(f"Ingest: {candidate.name} score={candidate.score} reason={reason}")
        try:
            imported_iocs = send_bundle(
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
        state.mark_pulse(pulse_id)
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
