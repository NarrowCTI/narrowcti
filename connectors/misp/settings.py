from dataclasses import dataclass, field
from typing import Mapping

from connectors.misp.feed_adapter import MISPAdapterLimits
from core.contextual_scoring import (
    normalize_contextual_scoring_max_impact,
    normalize_contextual_scoring_mode,
    parse_contextual_scoring_impacts,
)
from core.graph_export_plan import normalize_graph_export_mode
from core.runtime_config import (
    env_bool as resolve_bool,
    env_bool_alias as resolve_bool_alias,
    env_int as resolve_int,
    env_int_alias as resolve_int_alias,
    env_list as resolve_list,
    env_required as resolve_required,
    environment,
    parse_misp_verify_tls,
)
from core.runtime_config import require_nonnegative, require_positive


@dataclass(frozen=True)
class MISPSettings:
    connector_name: str
    opencti_url: str
    opencti_token: str = field(repr=False)
    misp_url: str
    misp_key: str = field(repr=False)
    misp_queries: list[str]
    misp_verify_tls: bool
    misp_search_timeout: int
    misp_enrich_timeout: int
    misp_retries: int
    misp_retry_backoff_seconds: int
    misp_retry_jitter_seconds: int
    connector_run_interval: int
    ingest_pause_seconds: int
    dry_run: bool
    run_once: bool
    source_confidence: int
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
    graph_replay_on_artifact_dedup: bool
    ip_asn_enrichment_file: str
    state_file: str
    decision_audit_file: str
    quarantine_repository_file: str = ""
    quarantine_raw_snapshot_max_bytes: int = 65536
    contextual_scoring_mode: str = "shadow"
    contextual_scoring_max_impact: int = 100
    contextual_scoring_impacts: dict[str, int] = None
    enable_infrastructure_victimology_export: bool = False

    def __post_init__(self):
        if self.max_iocs_per_event < 1:
            raise ValueError("max_iocs_per_event must be greater than zero")
        for name in ("misp_search_timeout", "misp_enrich_timeout", "misp_retries"):
            require_positive(name, getattr(self, name))
        for name in ("misp_retry_backoff_seconds", "misp_retry_jitter_seconds"):
            require_nonnegative(name, getattr(self, name))

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

    def to_safe_dict(self) -> dict[str, object]:
        """Return a diagnostics-safe view without credentials."""

        return {
            "connector_name": self.connector_name,
            "opencti_url": self.opencti_url,
            "opencti_configured": bool(self.opencti_token),
            "misp_url": self.misp_url,
            "misp_configured": bool(self.misp_key),
            "misp_verify_tls": self.misp_verify_tls,
            "misp_queries": list(self.misp_queries),
            "dry_run": self.dry_run,
            "run_once": self.run_once,
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
    misp_queries = env_list("MISP_QUERIES", env)
    if not misp_queries:
        raise RuntimeError("Missing required variable: MISP_QUERIES")

    settings = MISPSettings(
        connector_name=env.get("CONNECTOR_NAME", "NarrowCTI Gateway"),
        opencti_url=env_required("OPENCTI_URL", env),
        opencti_token=env_required("OPENCTI_TOKEN", env),
        misp_url=env_required("MISP_URL", env),
        misp_key=env_required("MISP_KEY", env),
        misp_queries=misp_queries,
        misp_verify_tls=parse_misp_verify_tls(env.get("MISP_VERIFY_TLS")),
        misp_search_timeout=env_int("MISP_SEARCH_TIMEOUT", 45, env),
        misp_enrich_timeout=env_int("MISP_ENRICH_TIMEOUT", 60, env),
        misp_retries=env_int("MISP_RETRIES", 3, env),
        misp_retry_backoff_seconds=env_int("MISP_RETRY_BACKOFF_SECONDS", 3, env),
        misp_retry_jitter_seconds=env_int("MISP_RETRY_JITTER_SECONDS", 1, env),
        connector_run_interval=env_int("CONNECTOR_RUN_INTERVAL", 3600, env),
        ingest_pause_seconds=env_int("INGEST_PAUSE_SECONDS", 2, env),
        dry_run=env_bool("MISP_DRY_RUN", True, env),
        run_once=env_bool("MISP_RUN_ONCE", False, env),
        source_confidence=env_int("MISP_SOURCE_CONFIDENCE", 50, env),
        max_events_per_run=env_int("MISP_MAX_EVENTS_PER_RUN", 10, env),
        max_attributes_per_event=env_int("MISP_MAX_ATTRIBUTES_PER_EVENT", 1000, env),
        max_iocs_per_event=env_int("MISP_MAX_IOCS_PER_EVENT", 1000, env),
        oversized_event_action=env.get("MISP_OVERSIZED_EVENT_ACTION", "skip"),
        misp_from_date=env.get("MISP_FROM_DATE", ""),
        misp_to_date=env.get("MISP_TO_DATE", ""),
        misp_tags=env_list("MISP_TAGS", env),
        misp_published_only=env_bool("MISP_PUBLISHED_ONLY", False, env),
        min_score_to_ingest=env_int_with_gateway(
            "MIN_SCORE_TO_INGEST", "NARROWCTI_MIN_SCORE_TO_INGEST", 60, env
        ),
        max_days_old=env_int_with_gateway(
            "MAX_DAYS_OLD", "NARROWCTI_MAX_DAYS_OLD", 1095, env
        ),
        min_score_for_old_event=env_int("MIN_SCORE_FOR_OLD_EVENT", 80, env),
        max_days_hard_filter=env_int("MAX_DAYS_HARD_FILTER", 0, env),
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
        graph_replay_on_artifact_dedup=env_bool_with_gateway(
            "MISP_GRAPH_REPLAY_ON_ARTIFACT_DEDUP",
            "NARROWCTI_GRAPH_REPLAY_ON_ARTIFACT_DEDUP",
            False,
            env,
        ),
        ip_asn_enrichment_file=env.get("NARROWCTI_IP_ASN_ENRICHMENT_FILE", ""),
        state_file=env.get("MISP_STATE_FILE", "/app/state/misp_state.json"),
        decision_audit_file=env.get("MISP_DECISION_AUDIT_FILE", ""),
        quarantine_repository_file=env.get(
            "MISP_QUARANTINE_REPOSITORY",
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
    )
    _ = settings.adapter_limits
    return settings
