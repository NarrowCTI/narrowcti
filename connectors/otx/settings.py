import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    connector_name: str
    opencti_url: str
    opencti_token: str
    otx_api_key: str
    otx_queries: list[str]
    otx_timeout: int
    otx_search_timeout: int
    otx_retries: int
    otx_retry_backoff_seconds: int
    connector_run_interval: int
    max_days_old: int
    max_days_hard_filter: int
    max_pulses_per_query: int
    max_search_results_per_query: int
    max_iocs_per_pulse: int
    ingest_pause_seconds: int
    dry_run: bool
    source_confidence: int
    min_score_for_old_pulse: int
    min_score_to_ingest: int
    enable_quarantine: bool
    quarantine_score_threshold: int
    allowed_tlp: list[str]
    allowed_indicator_types: list[str]
    state_file: str
    decision_audit_file: str


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


def env_int_with_gateway(name, gateway_name, default):
    value = os.getenv(name)
    if value is None:
        value = os.getenv(gateway_name)
    if value is None:
        return default
    return int(value)


def env_bool_with_gateway(name, gateway_name, default=False):
    value = os.getenv(name)
    if value is None:
        value = os.getenv(gateway_name)
    if value is None:
        return default
    return value.lower() in ["true", "1", "yes"]


def env_list(name):
    return [value.strip() for value in os.getenv(name, "").split(",") if value.strip()]


def load_settings():
    otx_queries = env_list("OTX_QUERIES")
    if not otx_queries:
        raise RuntimeError("Missing required variable: OTX_QUERIES")

    max_pulses_per_query = env_int("MAX_PULSES_PER_QUERY", 5)
    max_search_results_per_query = max(
        env_int("MAX_SEARCH_RESULTS_PER_QUERY", max(max_pulses_per_query, 10)),
        max_pulses_per_query,
    )

    return Settings(
        connector_name=os.getenv("CONNECTOR_NAME", "NarrowCTI Gateway"),
        opencti_url=env_required("OPENCTI_URL"),
        opencti_token=env_required("OPENCTI_TOKEN"),
        otx_api_key=env_required("OTX_API_KEY"),
        otx_queries=otx_queries,
        otx_timeout=env_int("OTX_TIMEOUT", 60),
        otx_search_timeout=env_int("OTX_SEARCH_TIMEOUT", 45),
        otx_retries=env_int("OTX_RETRIES", 3),
        otx_retry_backoff_seconds=env_int("OTX_RETRY_BACKOFF_SECONDS", 3),
        connector_run_interval=env_int("CONNECTOR_RUN_INTERVAL", 3600),
        max_days_old=env_int_with_gateway(
            "MAX_DAYS_OLD",
            "NARROWCTI_MAX_DAYS_OLD",
            1095,
        ),
        max_days_hard_filter=env_int("MAX_DAYS_HARD_FILTER", 0),
        max_pulses_per_query=max_pulses_per_query,
        max_search_results_per_query=max_search_results_per_query,
        max_iocs_per_pulse=env_int("MAX_IOCS_PER_PULSE", 2000),
        ingest_pause_seconds=env_int("INGEST_PAUSE_SECONDS", 2),
        dry_run=env_bool("OTX_DRY_RUN", env_bool("NARROWCTI_DRY_RUN", False)),
        source_confidence=env_int("OTX_SOURCE_CONFIDENCE", 50),
        min_score_for_old_pulse=env_int("MIN_SCORE_FOR_OLD_PULSE", 80),
        min_score_to_ingest=env_int_with_gateway(
            "MIN_SCORE_TO_INGEST",
            "NARROWCTI_MIN_SCORE_TO_INGEST",
            60,
        ),
        enable_quarantine=env_bool_with_gateway(
            "ENABLE_QUARANTINE",
            "NARROWCTI_ENABLE_QUARANTINE",
            True,
        ),
        quarantine_score_threshold=env_int_with_gateway(
            "QUARANTINE_SCORE_THRESHOLD",
            "NARROWCTI_QUARANTINE_SCORE_THRESHOLD",
            50,
        ),
        allowed_tlp=env_list("NARROWCTI_ALLOWED_TLP"),
        allowed_indicator_types=env_list("NARROWCTI_ALLOWED_INDICATOR_TYPES"),
        state_file=os.getenv("STATE_FILE", "/app/state/state.json"),
        decision_audit_file=os.getenv("DECISION_AUDIT_FILE", ""),
    )
