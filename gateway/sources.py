import os
from dataclasses import replace

from pycti import OpenCTIApiClient

from connectors.misp.client import MISPClient
from connectors.misp.feed_adapter import MISPFeedAdapter
from connectors.misp.processor import MISPProcessor
from connectors.misp.settings import load_settings as load_misp_settings
from connectors.otx.feed_adapter import OTXFeedAdapter
from connectors.otx.otx_client import OTXClient
from connectors.otx.processor import OTXProcessor
from connectors.otx.settings import load_settings as load_otx_settings
from core.decision_audit import DecisionAuditLog
from core.deduplication import ArtifactDeduplicationIndex
from core.opencti_deduplication import (
    CompositeArtifactDeduplication,
    OpenCTIArtifactLookup,
)
from gateway.runtime import SourceRegistry


SOURCE_RUNTIME_PATHS = {
    "otx": {
        "state_env": "STATE_FILE",
        "state_file": "otx_state.json",
        "audit_env": "DECISION_AUDIT_FILE",
        "audit_file": "otx_decisions.jsonl",
    },
    "misp": {
        "state_env": "MISP_STATE_FILE",
        "state_file": "misp_state.json",
        "audit_env": "MISP_DECISION_AUDIT_FILE",
        "audit_file": "misp_decisions.jsonl",
    },
}


class ProcessorRunner:
    def __init__(self, key, name, processor):
        self.key = key
        self.name = name
        self.processor = processor

    def run_once(self):
        return self.processor.run_once()


def build_source_dedup(api_client, artifact_dedup, opencti_dedup_lookup, logger):
    if not artifact_dedup and not opencti_dedup_lookup:
        return None

    lookup = None
    if opencti_dedup_lookup:
        lookup = OpenCTIArtifactLookup(api_client, logger=logger)

    return CompositeArtifactDeduplication(
        local_index=artifact_dedup,
        opencti_lookup=lookup,
        logger=logger,
    )


def gateway_file(gateway_settings, directory_name, filename):
    base_dir = getattr(gateway_settings, directory_name, "")
    if not base_dir:
        return ""
    return os.path.join(base_dir, filename)


def apply_gateway_source_paths(settings, gateway_settings, source_key):
    if not gateway_settings:
        return settings

    path_config = SOURCE_RUNTIME_PATHS[source_key]
    updates = {}
    if path_config["state_env"] not in os.environ:
        updates["state_file"] = gateway_file(
            gateway_settings,
            "state_dir",
            path_config["state_file"],
        )
    if path_config["audit_env"] not in os.environ:
        updates["decision_audit_file"] = gateway_file(
            gateway_settings,
            "decision_audit_dir",
            path_config["audit_file"],
        )
    return replace(settings, **updates) if updates else settings


def build_otx_runner(
    logger,
    artifact_dedup=None,
    opencti_dedup_lookup=False,
    gateway_settings=None,
):
    settings = apply_gateway_source_paths(load_otx_settings(), gateway_settings, "otx")
    api = OpenCTIApiClient(settings.opencti_url, settings.opencti_token)
    dedup = build_source_dedup(api, artifact_dedup, opencti_dedup_lookup, logger)
    otx = OTXClient(
        settings.otx_api_key,
        search_timeout=settings.otx_search_timeout,
        enrich_timeout=settings.otx_timeout,
        retries=settings.otx_retries,
        retry_backoff_seconds=settings.otx_retry_backoff_seconds,
        logger=logger,
    )
    processor = OTXProcessor(
        settings,
        otx,
        api,
        logger,
        ingest_pause_seconds=settings.ingest_pause_seconds,
        feed_adapter=OTXFeedAdapter(otx),
        decision_audit=DecisionAuditLog(settings.decision_audit_file),
        artifact_dedup=dedup,
    )
    return ProcessorRunner("otx", "OTX", processor)


def build_misp_runner(
    logger,
    artifact_dedup=None,
    opencti_dedup_lookup=False,
    gateway_settings=None,
):
    settings = apply_gateway_source_paths(load_misp_settings(), gateway_settings, "misp")
    api = OpenCTIApiClient(settings.opencti_url, settings.opencti_token)
    dedup = build_source_dedup(api, artifact_dedup, opencti_dedup_lookup, logger)
    misp = MISPClient(
        settings.misp_url,
        settings.misp_key,
        search_timeout=settings.misp_search_timeout,
        enrich_timeout=settings.misp_enrich_timeout,
        retries=settings.misp_retries,
        retry_backoff_seconds=settings.misp_retry_backoff_seconds,
        verify_tls=settings.misp_verify_tls,
        logger=logger,
    )
    adapter = MISPFeedAdapter(
        misp,
        limits=settings.adapter_limits,
        logger=logger,
        search_filters=settings.search_filters,
    )
    processor = MISPProcessor(
        settings,
        misp,
        api,
        logger,
        ingest_pause_seconds=settings.ingest_pause_seconds,
        feed_adapter=adapter,
        decision_audit=DecisionAuditLog(settings.decision_audit_file),
        artifact_dedup=dedup,
    )
    return ProcessorRunner("misp", "MISP", processor)


def build_artifact_dedup(gateway_settings):
    if not gateway_settings:
        return None
    if gateway_settings.dedup_mode not in ["artifact", "hybrid"]:
        return None
    return ArtifactDeduplicationIndex(gateway_settings.dedup_state_file)


def default_source_registry(logger, gateway_settings=None):
    artifact_dedup = build_artifact_dedup(gateway_settings)
    opencti_dedup_lookup = bool(
        gateway_settings and gateway_settings.opencti_dedup_lookup
    )
    return (
        SourceRegistry()
        .register(
            "otx",
            "OTX",
            lambda: build_otx_runner(
                logger,
                artifact_dedup,
                opencti_dedup_lookup,
                gateway_settings,
            ),
        )
        .register(
            "misp",
            "MISP",
            lambda: build_misp_runner(
                logger,
                artifact_dedup,
                opencti_dedup_lookup,
                gateway_settings,
            ),
        )
    )
