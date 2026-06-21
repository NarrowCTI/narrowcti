import os
from dataclasses import dataclass

from connectors.misp.feed_adapter import MISPAdapterLimits


@dataclass(frozen=True)
class MISPSettings:
    connector_name: str
    opencti_url: str
    opencti_token: str
    misp_url: str
    misp_key: str
    misp_queries: list[str]
    misp_verify_tls: bool
    misp_search_timeout: int
    misp_enrich_timeout: int
    misp_retries: int
    misp_retry_backoff_seconds: int
    connector_run_interval: int
    ingest_pause_seconds: int
    dry_run: bool
    run_once: bool
    max_events_per_run: int
    max_attributes_per_event: int
    max_iocs_per_event: int
    oversized_event_action: str
    misp_from_date: str
    misp_to_date: str
    misp_tags: list[str]
    misp_published_only: bool
    min_score_to_ingest: int
    max_days_old: int
    min_score_for_old_event: int
    max_days_hard_filter: int
    enable_quarantine: bool
    quarantine_score_threshold: int
    state_file: str
    decision_audit_file: str

    def __post_init__(self):
        if self.max_iocs_per_event < 1:
            raise ValueError("max_iocs_per_event must be greater than zero")

    @property
    def adapter_limits(self):
        return MISPAdapterLimits(
            max_events_per_run=self.max_events_per_run,
            max_attributes_per_event=self.max_attributes_per_event,
            oversized_event_action=self.oversized_event_action,
        )

    @property
    def search_filters(self):
        filters = {}
        if self.misp_from_date:
            filters["from"] = self.misp_from_date
        if self.misp_to_date:
            filters["to"] = self.misp_to_date
        if self.misp_tags:
            filters["tags"] = self.misp_tags
        if self.misp_published_only:
            filters["published"] = True
        return filters


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
    return [value.strip() for value in os.getenv(name, "").split(",") if value.strip()]


def load_settings():
    misp_queries = env_list("MISP_QUERIES")
    if not misp_queries:
        raise RuntimeError("Missing required variable: MISP_QUERIES")

    settings = MISPSettings(
        connector_name=os.getenv("CONNECTOR_NAME", "NarrowCTI Gateway"),
        opencti_url=env_required("OPENCTI_URL"),
        opencti_token=env_required("OPENCTI_TOKEN"),
        misp_url=env_required("MISP_URL"),
        misp_key=env_required("MISP_KEY"),
        misp_queries=misp_queries,
        misp_verify_tls=env_bool("MISP_VERIFY_TLS", False),
        misp_search_timeout=env_int("MISP_SEARCH_TIMEOUT", 45),
        misp_enrich_timeout=env_int("MISP_ENRICH_TIMEOUT", 60),
        misp_retries=env_int("MISP_RETRIES", 3),
        misp_retry_backoff_seconds=env_int("MISP_RETRY_BACKOFF_SECONDS", 3),
        connector_run_interval=env_int("CONNECTOR_RUN_INTERVAL", 3600),
        ingest_pause_seconds=env_int("INGEST_PAUSE_SECONDS", 2),
        dry_run=env_bool("MISP_DRY_RUN", True),
        run_once=env_bool("MISP_RUN_ONCE", False),
        max_events_per_run=env_int("MISP_MAX_EVENTS_PER_RUN", 10),
        max_attributes_per_event=env_int("MISP_MAX_ATTRIBUTES_PER_EVENT", 1000),
        max_iocs_per_event=env_int("MISP_MAX_IOCS_PER_EVENT", 1000),
        oversized_event_action=os.getenv("MISP_OVERSIZED_EVENT_ACTION", "skip"),
        misp_from_date=os.getenv("MISP_FROM_DATE", ""),
        misp_to_date=os.getenv("MISP_TO_DATE", ""),
        misp_tags=env_list("MISP_TAGS"),
        misp_published_only=env_bool("MISP_PUBLISHED_ONLY", False),
        min_score_to_ingest=env_int("MIN_SCORE_TO_INGEST", 60),
        max_days_old=env_int("MAX_DAYS_OLD", 1095),
        min_score_for_old_event=env_int("MIN_SCORE_FOR_OLD_EVENT", 80),
        max_days_hard_filter=env_int("MAX_DAYS_HARD_FILTER", 0),
        enable_quarantine=env_bool("ENABLE_QUARANTINE", True),
        quarantine_score_threshold=env_int("QUARANTINE_SCORE_THRESHOLD", 50),
        state_file=os.getenv("MISP_STATE_FILE", "/app/state/misp_state.json"),
        decision_audit_file=os.getenv("MISP_DECISION_AUDIT_FILE", ""),
    )
    settings.adapter_limits
    return settings
