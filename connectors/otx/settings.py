from dataclasses import dataclass, field
from typing import Mapping

from core.contextual_scoring import (
    normalize_contextual_scoring_max_impact,
    normalize_contextual_scoring_mode,
    parse_contextual_scoring_impacts,
)
from core.graph_export_plan import normalize_graph_export_mode
from core.mitre_attack import DEFAULT_MITRE_STIX_URL
from core.runtime_config import (
    env_bool as resolve_bool,
    env_bool_alias as resolve_bool_alias,
    env_int as resolve_int,
    env_int_alias as resolve_int_alias,
    env_list as resolve_list,
    env_required as resolve_required,
    environment,
    require_nonnegative,
    require_positive,
)


@dataclass(frozen=True)
class Settings:
    connector_name: str
    opencti_url: str
    opencti_token: str = field(repr=False)
    otx_api_key: str = field(repr=False)
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

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "connector_name": self.connector_name,
            "opencti_url": self.opencti_url,
            "opencti_configured": bool(self.opencti_token),
            "otx_configured": bool(self.otx_api_key),
            "otx_queries": list(self.otx_queries),
            "dry_run": self.dry_run,
            "graph_export_mode": self.graph_export_mode,
        }


def env_required(name, environ=None):
    return resolve_required(environment(environ), name)


def env_int(name, default, environ=None):
    return resolve_int(environment(environ), name, default)


def env_bool(name, default=False, environ=None):
    return resolve_bool(environment(environ), name, default)


def env_int_with_gateway(name, gateway_name, default, environ=None):
    return resolve_int_alias(environment(environ), name, gateway_name, default)


def env_bool_with_gateway(name, gateway_name, default=False, environ=None):
    return resolve_bool_alias(environment(environ), name, gateway_name, default)


def env_list(name, environ=None):
    return resolve_list(environment(environ), name)


def load_settings(environ: Mapping[str, str] | None = None):
    env = environment(environ)
    otx_queries = env_list("OTX_QUERIES", env)
    if not otx_queries:
        raise RuntimeError("Missing required variable: OTX_QUERIES")

    max_pulses_per_query = env_int("MAX_PULSES_PER_QUERY", 5, env)
    max_search_results_per_query = max(
        env_int("MAX_SEARCH_RESULTS_PER_QUERY", max(max_pulses_per_query, 10), env),
        max_pulses_per_query,
    )

    return Settings(
        connector_name=env.get("CONNECTOR_NAME", "NarrowCTI Gateway"),
        opencti_url=env_required("OPENCTI_URL", env),
        opencti_token=env_required("OPENCTI_TOKEN", env),
        otx_api_key=env_required("OTX_API_KEY", env),
        otx_queries=otx_queries,
        otx_timeout=env_int("OTX_TIMEOUT", 60, env),
        otx_search_timeout=env_int("OTX_SEARCH_TIMEOUT", 45, env),
        otx_retries=env_int("OTX_RETRIES", 3, env),
        otx_retry_backoff_seconds=env_int("OTX_RETRY_BACKOFF_SECONDS", 3, env),
        otx_retry_jitter_seconds=env_int("OTX_RETRY_JITTER_SECONDS", 1, env),
        connector_run_interval=env_int("CONNECTOR_RUN_INTERVAL", 3600, env),
        max_days_old=env_int_with_gateway(
            "MAX_DAYS_OLD", "NARROWCTI_MAX_DAYS_OLD", 1095, env
        ),
        max_days_hard_filter=env_int("MAX_DAYS_HARD_FILTER", 0, env),
        max_pulses_per_query=max_pulses_per_query,
        max_search_results_per_query=max_search_results_per_query,
        max_iocs_per_pulse=env_int("MAX_IOCS_PER_PULSE", 2000, env),
        ingest_pause_seconds=env_int("INGEST_PAUSE_SECONDS", 2, env),
        dry_run=env_bool("OTX_DRY_RUN", env_bool("NARROWCTI_DRY_RUN", False, env), env),
        source_confidence=env_int("OTX_SOURCE_CONFIDENCE", 50, env),
        min_score_for_old_pulse=env_int("MIN_SCORE_FOR_OLD_PULSE", 80, env),
        min_score_to_ingest=env_int_with_gateway(
            "MIN_SCORE_TO_INGEST", "NARROWCTI_MIN_SCORE_TO_INGEST", 60, env
        ),
        enable_quarantine=env_bool_with_gateway(
            "ENABLE_QUARANTINE", "NARROWCTI_ENABLE_QUARANTINE", True, env
        ),
        quarantine_score_threshold=env_int_with_gateway(
            "QUARANTINE_SCORE_THRESHOLD",
            "NARROWCTI_QUARANTINE_SCORE_THRESHOLD",
            50,
            env,
        ),
        allowed_tlp=env_list("NARROWCTI_ALLOWED_TLP", env),
        allowed_indicator_types=env_list("NARROWCTI_ALLOWED_INDICATOR_TYPES", env),
        graph_min_entity_confidence=env_int("NARROWCTI_MIN_ENTITY_CONFIDENCE", 0, env),
        graph_min_relationship_confidence=env_int(
            "NARROWCTI_MIN_RELATIONSHIP_CONFIDENCE", 0, env
        ),
        graph_require_relationship_provenance=env_bool(
            "NARROWCTI_REQUIRE_RELATIONSHIP_PROVENANCE", False, env
        ),
        graph_allowed_entity_types=env_list(
            "NARROWCTI_ALLOWED_GRAPH_ENTITY_TYPES", env
        ),
        graph_allowed_stix_object_types=env_list(
            "NARROWCTI_ALLOWED_GRAPH_STIX_OBJECT_TYPES", env
        ),
        graph_export_mode=normalize_graph_export_mode(
            env.get("NARROWCTI_GRAPH_EXPORT_MODE", "audit")
        ),
        graph_dedup_state_file=env.get("NARROWCTI_GRAPH_DEDUP_STATE_FILE", ""),
        opencti_graph_lookup=env_bool("NARROWCTI_OPENCTI_GRAPH_LOOKUP", False, env),
        state_file=env.get("STATE_FILE", "/app/state/state.json"),
        decision_audit_file=env.get("DECISION_AUDIT_FILE", ""),
        quarantine_repository_file=env.get(
            "OTX_QUARANTINE_REPOSITORY",
            env.get("NARROWCTI_QUARANTINE_REPOSITORY", ""),
        ),
        quarantine_raw_snapshot_max_bytes=env_int(
            "NARROWCTI_QUARANTINE_RAW_SNAPSHOT_MAX_BYTES", 65536, env
        ),
        contextual_scoring_mode=normalize_contextual_scoring_mode(
            env.get("NARROWCTI_CONTEXTUAL_SCORING_MODE", "shadow")
        ),
        contextual_scoring_max_impact=normalize_contextual_scoring_max_impact(
            env_int("NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT", 100, env)
        ),
        contextual_scoring_impacts=parse_contextual_scoring_impacts(
            env.get("NARROWCTI_CONTEXTUAL_SCORING_IMPACTS", "")
        ),
        enable_infrastructure_victimology_export=env_bool(
            "NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT", False, env
        ),
        enable_otx_entity_extraction=env_bool(
            "NARROWCTI_ENABLE_OTX_ENTITY_EXTRACTION", True, env
        ),
        enable_mitre_attack_resolution=env_bool(
            "NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION", True, env
        ),
        mitre_cache_file=env.get("NARROWCTI_MITRE_CACHE_FILE", ""),
        mitre_stix_url=env.get("NARROWCTI_MITRE_STIX_URL", DEFAULT_MITRE_STIX_URL),
    )
