import os
import time
from pycti import OpenCTIApiClient

from core.scoring import age_days, calculate_score
from core.policy import should_ingest
from core.state_repository import load_state, save_state
from exporters.opencti import send_bundle
from otx_client import OTXClient


def env_required(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required variable: {name}")
    return value


def env_int(name, default):
    return int(os.getenv(name, str(default)))


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ["true", "1", "yes"]


def env_list(name):
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]


OPENCTI_URL = env_required("OPENCTI_URL")
OPENCTI_TOKEN = env_required("OPENCTI_TOKEN")
OTX_API_KEY = env_required("OTX_API_KEY")
OTX_QUERIES = env_list("OTX_QUERIES")
OTX_TIMEOUT = env_int("OTX_TIMEOUT", 60)
OTX_SEARCH_TIMEOUT = env_int("OTX_SEARCH_TIMEOUT", 45)
OTX_RETRIES = env_int("OTX_RETRIES", 3)
OTX_RETRY_BACKOFF_SECONDS = env_int("OTX_RETRY_BACKOFF_SECONDS", 3)
CONNECTOR_RUN_INTERVAL = env_int("CONNECTOR_RUN_INTERVAL", 3600)
MAX_DAYS_OLD = env_int("MAX_DAYS_OLD", 1095)
MAX_DAYS_HARD_FILTER = env_int("MAX_DAYS_HARD_FILTER", 0)
MAX_PULSES_PER_QUERY = env_int("MAX_PULSES_PER_QUERY", 5)
MAX_SEARCH_RESULTS_PER_QUERY = env_int(
    "MAX_SEARCH_RESULTS_PER_QUERY",
    max(MAX_PULSES_PER_QUERY, 10),
)
MAX_IOCS_PER_PULSE = env_int("MAX_IOCS_PER_PULSE", 2000)
MIN_SCORE_FOR_OLD_PULSE = env_int("MIN_SCORE_FOR_OLD_PULSE", 80)
MIN_SCORE_TO_INGEST = env_int("MIN_SCORE_TO_INGEST", 60)
ENABLE_QUARANTINE = env_bool("ENABLE_QUARANTINE", True)
QUARANTINE_SCORE_THRESHOLD = env_int("QUARANTINE_SCORE_THRESHOLD", 50)
STATE_FILE = os.getenv("STATE_FILE", "/app/state/state.json")

api = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def age_label(age):
    if age is None:
        return "unknown"
    return f"{age}d"


otx = OTXClient(
    OTX_API_KEY,
    search_timeout=OTX_SEARCH_TIMEOUT,
    enrich_timeout=OTX_TIMEOUT,
    retries=OTX_RETRIES,
    retry_backoff_seconds=OTX_RETRY_BACKOFF_SECONDS,
    logger=log,
)


def run():
    state = load_state(STATE_FILE)

    for query in OTX_QUERIES:
        log(f"Query: {query}")
        pulses = otx.search_pulses(query)
        ingested = 0
        reviewed = 0

        for pulse in pulses[:MAX_SEARCH_RESULTS_PER_QUERY]:
            if ingested >= MAX_PULSES_PER_QUERY:
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

            if ioc_count > MAX_IOCS_PER_PULSE:
                indicators = indicators[:MAX_IOCS_PER_PULSE]

            score = calculate_score(full, query)
            log(
                f"Candidate: {name} age={age_label(age)} "
                f"iocs={ioc_count} score={score}"
            )
            decision, reason = should_ingest(
                full,
                score,
                QUARANTINE_SCORE_THRESHOLD,
                ENABLE_QUARANTINE,
                MIN_SCORE_TO_INGEST,
                MAX_DAYS_OLD,
                MIN_SCORE_FOR_OLD_PULSE,
                MAX_DAYS_HARD_FILTER,
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
            save_state(STATE_FILE, state)
            ingested += 1
            time.sleep(2)

        log(
            f"Query summary: {query} reviewed={reviewed} "
            f"ingested={ingested} available={len(pulses)}"
        )


while True:
    run()
    log(f"Sleeping {CONNECTOR_RUN_INTERVAL}s")
    time.sleep(CONNECTOR_RUN_INTERVAL)
