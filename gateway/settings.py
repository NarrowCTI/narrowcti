import os
from dataclasses import dataclass


@dataclass(frozen=True)
class GatewaySettings:
    mode: str
    enabled_sources: list[str]
    dry_run: bool
    run_once: bool
    source_interval_seconds: int
    state_dir: str
    decision_audit_dir: str
    run_summary_file: str
    dedup_mode: str
    opencti_dedup_lookup: bool
    dedup_state_file: str

    def __post_init__(self):
        if not self.enabled_sources:
            raise ValueError("enabled_sources must contain at least one source")
        if self.source_interval_seconds < 1:
            raise ValueError("source_interval_seconds must be greater than zero")
        if self.dedup_mode not in ["off", "source", "artifact", "hybrid"]:
            raise ValueError("dedup_mode must be off, source, artifact or hybrid")


def env_int(name, default):
    return int(os.getenv(name, str(default)))


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ["true", "1", "yes"]


def env_list(name, default=""):
    raw = os.getenv(name, default)
    return [value.strip().lower() for value in raw.split(",") if value.strip()]


def load_settings():
    legacy_interval = env_int("CONNECTOR_RUN_INTERVAL", 3600)

    return GatewaySettings(
        mode=os.getenv("NARROWCTI_MODE", "gateway"),
        enabled_sources=env_list("NARROWCTI_ENABLED_SOURCES", "otx"),
        dry_run=env_bool("NARROWCTI_DRY_RUN", False),
        run_once=env_bool("NARROWCTI_RUN_ONCE", False),
        source_interval_seconds=env_int(
            "NARROWCTI_SOURCE_INTERVAL_SECONDS",
            legacy_interval,
        ),
        state_dir=os.getenv("NARROWCTI_STATE_DIR", "/app/state"),
        decision_audit_dir=os.getenv("NARROWCTI_DECISION_AUDIT_DIR", "/app/state/audit"),
        run_summary_file=os.getenv("NARROWCTI_RUN_SUMMARY_FILE", ""),
        dedup_mode=os.getenv("NARROWCTI_DEDUP_MODE", "source").lower(),
        opencti_dedup_lookup=env_bool("NARROWCTI_OPENCTI_DEDUP_LOOKUP", False),
        dedup_state_file=os.getenv(
            "NARROWCTI_DEDUP_STATE_FILE",
            "/app/state/dedup_index.json",
        ),
    )
