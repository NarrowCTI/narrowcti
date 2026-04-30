import time
from pycti import OpenCTIApiClient

from core.scoring import age_days, calculate_score
from core.policy import should_ingest
from core.state_repository import load_state, save_state
from exporters.opencti import send_bundle
from otx_client import OTXClient
from settings import load_settings


settings = load_settings()
api = OpenCTIApiClient(settings.opencti_url, settings.opencti_token)


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


otx = OTXClient(
    settings.otx_api_key,
    search_timeout=settings.otx_search_timeout,
    enrich_timeout=settings.otx_timeout,
    retries=settings.otx_retries,
    retry_backoff_seconds=settings.otx_retry_backoff_seconds,
    logger=log,
)


def run():
    state = load_state(settings.state_file)

    for query in settings.otx_queries:
        log(f"Query: {query}")
        pulses = otx.search_pulses(query)
        ingested = 0
        reviewed = 0

        for pulse in pulses[:settings.max_search_results_per_query]:
            if ingested >= settings.max_pulses_per_query:
                break

            pid = pulse.get("id")
            reviewed += 1

            if pid in state["pulses"]:
                log(f"Skip state: {pulse.get('name')}")
                continue

            full = otx.enrich_pulse(pid)
            if not full:
                log(f"Skip enrich failed: {pulse.get('name')}")
                continue

            name = full.get("name")
            indicators = full.get("indicators", [])
            ioc_count = len(indicators)
            age = age_days(full.get("created"))

            if ioc_count > settings.max_iocs_per_pulse:
                indicators = indicators[: settings.max_iocs_per_pulse]

            score = calculate_score(full, query)
            log(
                f"Candidate: {name} age={age_label(age)} "
                f"iocs={ioc_count} score={score}"
            )
            decision, reason = should_ingest(
                full,
                score,
                settings.quarantine_score_threshold,
                settings.enable_quarantine,
                settings.min_score_to_ingest,
                settings.max_days_old,
                settings.min_score_for_old_pulse,
                settings.max_days_hard_filter,
            )

            if decision == "quarantine":
                log(f"Quarantine: {name} score={score} reason={reason}")
                continue

            if decision is False:
                log(f"Drop: {name} score={score} reason={reason}")
                continue

            log(f"Ingest: {name} score={score} reason={reason}")
            try:
                imported_iocs = send_bundle(
                    api,
                    name,
                    full.get("description", ""),
                    score,
                    indicators,
                )
            except Exception as exc:
                log(f"Ingest failed: {name} error={exc}")
                continue
            log(f"Ingest complete: {name} indicators={imported_iocs}")

            state["pulses"].append(pid)
            save_state(settings.state_file, state)
            ingested += 1
            time.sleep(2)

        log(
            f"Query summary: {query} reviewed={reviewed} "
            f"ingested={ingested} available={len(pulses)}"
        )


while True:
    run()
    log(f"Sleeping {settings.connector_run_interval}s")
    time.sleep(settings.connector_run_interval)
