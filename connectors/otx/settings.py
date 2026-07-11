import os
from dataclasses import dataclass

from core.contextual_scoring import (
    normalize_contextual_scoring_max_impact,
    normalize_contextual_scoring_mode,
    parse_contextual_scoring_impacts,
)
from core.graph_export_plan import normalize_graph_export_mode
from core.mitre_attack import DEFAULT_MITRE_STIX_URL
from core.runtime_config import require_nonnegative, require_positive


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
    otx_retry_jitter_seconds: int
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
    graph_min_entity_confidence: int
    graph_min_relationship_confidence: int
    graph_require_relationship_provenance: bool
    graph_allowed_entity_types: list[str]
    graph_allowed_stix_object_types: list[str]
    graph_export_mode: str
    graph_dedup_state_file: str
    opencti_graph_lookup: bool
    state_file: str
    decision_audit_file: str
    quarantine_repository_file: str = ""
    quarantine_raw_snapshot_max_bytes: int = 65536
    contextual_scoring_mode: str = "shadow"
    contextual_scoring_max_impact: int = 100
    contextual_scoring_impacts: dict[str, int] = None
    enable_infrastructure_victimology_export: bool = False
    enable_otx_entity_extraction: bool = True
    enable_mitre_attack_resolution: bool = True
    mitre_cache_file: str = ""
    mitre_stix_url: str = DEFAULT_MITRE_STIX_URL

    def __post_init__(self):
        for name in ("otx_timeout", "otx_search_timeout", "otx_retries"):
            require_positive(name, getattr(self, name))
        for name in ("otx_retry_backoff_seconds", "otx_retry_jitter_seconds"):
            require_nonnegative(name, getattr(self, name))


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
        otx_retry_jitter_seconds=env_int("OTX_RETRY_JITTER_SECONDS", 1),
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
        graph_min_entity_confidence=env_int("NARROWCTI_MIN_ENTITY_CONFIDENCE", 0),
        graph_min_relationship_confidence=env_int(
            "NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE",
            0,
        ),
        graph_require_relationship_provenance=env_bool(
            "NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE",
            False,
        ),
        graph_allowed_entity_types=env_list("NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES"),
        graph_allowed_stix_object_types=env_list(
            "NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES"
        ),
        graph_export_mode=normalize_graph_export_mode(
            os.getenv("NARROWCTI_GRAPH_EXPORT_MODE", "audit")
        ),
        graph_dedup_state_file=os.getenv("NARROWCTI_GRAPH_DEDUP_STATE_FILE", ""),
        opencti_graph_lookup=env_bool("NARROWCTI_OPENCTI_GRAPH_LOOKUP", False),
        state_file=os.getenv("STATE_FILE", "/app/state/state.json"),
        decision_audit_file=os.getenv("DECISION_AUDIT_FILE", ""),
        quarantine_repository_file=os.getenv(
            "OTX_QUARANTINE_REPOSITORY",
            os.getenv("NARROWCTI_QUARANTINE_REPOSITORY", ""),
        ),
        quarantine_raw_snapshot_max_bytes=env_int(
            "NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES",
            65536,
        ),
        contextual_scoring_mode=normalize_contextual_scoring_mode(
            os.getenv("NARROWCTI_CONTEXTUAL_SCORING_MODE", "shadow")
        ),
        contextual_scoring_max_impact=normalize_contextual_scoring_max_impact(
            env_int("NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT", 100)
        ),
        contextual_scoring_impacts=parse_contextual_scoring_impacts(
            os.getenv("NARROWCTI_CONTEXTUAL_SCORING_IMPACTS", "")
        ),
        enable_infrastructure_victimology_export=env_bool(
            "NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT",
            False,
        ),
        enable_otx_entity_extraction=env_bool(
            "NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION",
            True,
        ),
        enable_mitre_attack_resolution=env_bool(
            "NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION",
            True,
        ),
        mitre_cache_file=os.getenv("NARROWCTI_MITRE_CACHE_FILE", ""),
        mitre_stix_url=os.getenv(
            "NARROWCTI_MITRE_STIX_URL",
            DEFAULT_MITRE_STIX_URL,
        ),
    )
