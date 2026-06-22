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
from gateway.runtime import SourceRegistry


class ProcessorRunner:
    def __init__(self, key, name, processor):
        self.key = key
        self.name = name
        self.processor = processor

    def run_once(self):
        return self.processor.run_once()


def build_otx_runner(logger):
    settings = load_otx_settings()
    api = OpenCTIApiClient(settings.opencti_url, settings.opencti_token)
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
    )
    return ProcessorRunner("otx", "OTX", processor)


def build_misp_runner(logger):
    settings = load_misp_settings()
    api = OpenCTIApiClient(settings.opencti_url, settings.opencti_token)
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
    )
    return ProcessorRunner("misp", "MISP", processor)


def default_source_registry(logger):
    return (
        SourceRegistry()
        .register("otx", "OTX", lambda: build_otx_runner(logger))
        .register("misp", "MISP", lambda: build_misp_runner(logger))
    )
