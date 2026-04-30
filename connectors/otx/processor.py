import time

from core.policy import should_ingest
from core.scoring import age_days, calculate_score
from core.state_repository import PulseStateRepository
from exporters.opencti import send_bundle


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


class OTXProcessor:
    def __init__(self, settings, otx_client, api_client, logger):
        self.settings = settings
        self.otx_client = otx_client
        self.api_client = api_client
        self.log = logger

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

        name = full.get("name")
        indicators = full.get("indicators", [])
        ioc_count = len(indicators)
        age = age_days(full.get("created"))

        if ioc_count > self.settings.max_iocs_per_pulse:
            indicators = indicators[: self.settings.max_iocs_per_pulse]

        score = calculate_score(full, query)
        self.log(
            f"Candidate: {name} age={age_label(age)} "
            f"iocs={ioc_count} score={score}"
        )

        decision, reason = should_ingest(
            full,
            score,
            self.settings.quarantine_score_threshold,
            self.settings.enable_quarantine,
            self.settings.min_score_to_ingest,
            self.settings.max_days_old,
            self.settings.min_score_for_old_pulse,
            self.settings.max_days_hard_filter,
        )

        if decision == "quarantine":
            self.log(f"Quarantine: {name} score={score} reason={reason}")
            return False

        if decision is False:
            self.log(f"Drop: {name} score={score} reason={reason}")
            return False

        self.log(f"Ingest: {name} score={score} reason={reason}")
        try:
            imported_iocs = send_bundle(
                self.api_client,
                name,
                full.get("description", ""),
                score,
                indicators,
                identity_name=self.settings.connector_name,
            )
        except Exception as exc:
            self.log(f"Ingest failed: {name} error={exc}")
            return False

        self.log(f"Ingest complete: {name} indicators={imported_iocs}")
        state.mark_pulse(pulse_id)
        return True
