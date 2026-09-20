"""Canonical GatewaySettings owner; behavior remains source-compatible."""

from __future__ import annotations

import os
from dataclasses import dataclass
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
    environment,
)


@dataclass(frozen=True)
class GatewaySettings:
    mode: str
    enabled_sources: list[str]
    dry_run: bool
    run_once: bool
    source_interval_seconds: int
    state_dir: str
    decision_audit_dir: str
    quarantine_repository_file: str
    run_summary_file: str
    min_score_to_ingest: int
    enable_quarantine: bool
    quarantine_score_threshold: int
    max_days_old: int
    allowed_tlp: list[str]
    allowed_indicator_types: list[str]
    dedup_mode: str
    opencti_dedup_lookup: bool
    dedup_state_file: str
    graph_export_mode: str
    graph_dedup_state_file: str
    opencti_graph_lookup: bool
    contextual_scoring_mode: str = "shadow"
    contextual_scoring_max_impact: int = 100
    contextual_scoring_impacts: dict[str, int] = None
    enable_infrastructure_victimology_export: bool = False
    declared_capabilities: list[str] = None
    release_audit_file: str = ""
    enable_mitre_attack_resolution: bool = True
    mitre_cache_file: str = ""
    mitre_stix_url: str = DEFAULT_MITRE_STIX_URL

    def __post_init__(self):
        if not self.enabled_sources:
            raise ValueError("enabled_sources must contain at least one source")
        if self.source_interval_seconds < 1:
            raise ValueError("source_interval_seconds must be greater than zero")
        if self.dedup_mode not in ["off", "source", "artifact", "hybrid"]:
            raise ValueError("dedup_mode must be off, source, artifact or hybrid")
        object.__setattr__(self, "contextual_scoring_mode", normalize_contextual_scoring_mode(self.contextual_scoring_mode))
        object.__setattr__(self, "contextual_scoring_max_impact", normalize_contextual_scoring_max_impact(self.contextual_scoring_max_impact))
        object.__setattr__(self, "contextual_scoring_impacts", parse_contextual_scoring_impacts(self.contextual_scoring_impacts))
        if self.declared_capabilities is None:
            object.__setattr__(self, "declared_capabilities", [])


def env_int(name, default, environ=None):
    return resolve_int(environment(environ), name, default)


def env_bool(name, default=False, environ=None):
    return resolve_bool(environment(environ), name, default)


def env_int_alias(primary, fallback, default, environ=None):
    return resolve_int_alias(environment(environ), primary, fallback, default)


def env_bool_alias(primary, fallback, default=False, environ=None):
    return resolve_bool_alias(environment(environ), primary, fallback, default)


def env_list(name, default="", environ=None):
    return [value.lower() for value in resolve_list(environment(environ), name, default)]


def load_settings(environ: Mapping[str, str] | None = None):
    env = environment(environ)
    legacy_interval = env_int("CONNECTOR_RUN_INTERVAL", 3600, env)
    state_dir = env.get("NARROWCTI_STATE_DIR", "/app/state")
    default_quarantine_file = os.path.join(state_dir, "quarantine.jsonl")
    default_release_audit_file = os.path.join(state_dir, "audit", "releases.jsonl")
    return GatewaySettings(
        mode=env.get("NARROWCTI_MODE", "gateway"),
        enabled_sources=env_list("NARROWCTI_ENABLED_SOURCES", "otx", env),
        dry_run=env_bool("NARROWCTI_DRY_RUN", False, env),
        run_once=env_bool("NARROWCTI_RUN_ONCE", False, env),
        source_interval_seconds=env_int("NARROWCTI_SOURCE_INTERVAL_SECONDS", legacy_interval, env),
        state_dir=state_dir,
        decision_audit_dir=env.get("NARROWCTI_DECISION_AUDIT_DIR", "/app/state/audit"),
        quarantine_repository_file=env.get("NARROWCTI_QUARANTINE_REPOSITORY", default_quarantine_file),
        run_summary_file=env.get("NARROWCTI_RUN_SUMMARY_FILE", ""),
        min_score_to_ingest=env_int_alias("NARROWCTI_MIN_SCORE_TO_INGEST", "MIN_SCORE_TO_INGEST", 60, env),
        enable_quarantine=env_bool_alias("NARROWCTI_ENABLE_QUARANTINE", "ENABLE_QUARANTINE", True, env),
        quarantine_score_threshold=env_int_alias("NARROWCTI_QUARANTINE_SCORE_THRESHOLD", "QUARANTINE_SCORE_THRESHOLD", 50, env),
        max_days_old=env_int_alias("NARROWCTI_MAX_DAYS_OLD", "MAX_DAYS_OLD", 1095, env),
        allowed_tlp=env_list("NARROWCTI_ALLOWED_TLP", environ=env),
        allowed_indicator_types=env_list("NARROWCTI_ALLOWED_INDICATOR_TYPES", environ=env),
        dedup_mode=env.get("NARROWCTI_DEDUP_MODE", "source").lower(),
        opencti_dedup_lookup=env_bool("NARROWCTI_OPENCTI_DEDUP_LOOKUP", False, env),
        dedup_state_file=env.get("NARROWCTI_DEDUP_STATE_FILE", "/app/state/dedup_index.json"),
        graph_export_mode=normalize_graph_export_mode(env.get("NARROWCTI_GRAPH_EXPORT_MODE", "audit")),
        graph_dedup_state_file=env.get("NARROWCTI_GRAPH_DEDUP_STATE_FILE", ""),
        opencti_graph_lookup=env_bool("NARROWCTI_OPENCTI_GRAPH_LOOKUP", False, env),
        contextual_scoring_mode=normalize_contextual_scoring_mode(env.get("NARROWCTI_CONTEXTUAL_SCORING_MODE", "shadow")),
        contextual_scoring_max_impact=normalize_contextual_scoring_max_impact(env_int("NARROWCTI_CONTEXTUAL_SCORING_MAX_IMPACT", 100, env)),
        contextual_scoring_impacts=parse_contextual_scoring_impacts(env.get("NARROWCTI_CONTEXTUAL_SCORING_IMPACTS", "")),
        enable_infrastructure_victimology_export=env_bool("NARROWCTI_ENABLE_INFRASTRUCTURE_VICTIMOLOGY_EXPORT", False, env),
        declared_capabilities=env_list("NARROWCTI_CAPABILITIES", environ=env),
        release_audit_file=env.get("NARROWCTI_RELEASE_AUDIT_FILE", default_release_audit_file),
        enable_mitre_attack_resolution=env_bool("NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION", True, env),
        mitre_cache_file=env.get("NARROWCTI_MITRE_CACHE_FILE", ""),
        mitre_stix_url=env.get("NARROWCTI_MITRE_STIX_URL", DEFAULT_MITRE_STIX_URL),
    )


__all__ = [
    "GatewaySettings", "env_int", "env_bool", "env_int_alias", "env_bool_alias",
    "env_list", "load_settings",
]

