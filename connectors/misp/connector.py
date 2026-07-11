from core.decision_audit import DecisionAuditLog
from connectors.misp.client import MISPClient
from connectors.misp.feed_adapter import MISPFeedAdapter
from connectors.misp.processor import MISPProcessor
from connectors.misp.runtime import run_processor_loop
from connectors.misp.settings import load_settings
from gateway.opencti_client import build_opencti_client


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def build_processor(settings):
    api = build_opencti_client(settings.opencti_url, settings.opencti_token)
    misp = MISPClient(
        settings.misp_url,
        settings.misp_key,
        search_timeout=settings.misp_search_timeout,
        enrich_timeout=settings.misp_enrich_timeout,
        retries=settings.misp_retries,
        retry_backoff_seconds=settings.misp_retry_backoff_seconds,
        retry_jitter_seconds=settings.misp_retry_jitter_seconds,
        verify_tls=settings.misp_verify_tls,
        logger=log,
    )
    adapter = MISPFeedAdapter(
        misp,
        limits=settings.adapter_limits,
        logger=log,
        search_filters=settings.search_filters,
    )
    return MISPProcessor(
        settings,
        misp,
        api,
        log,
        ingest_pause_seconds=settings.ingest_pause_seconds,
        feed_adapter=adapter,
        decision_audit=DecisionAuditLog(settings.decision_audit_file),
    )


def main():
    settings = load_settings()
    processor = build_processor(settings)
    if settings.run_once:
        processor.run_once()
        return
    run_processor_loop(processor, settings, log)


if __name__ == "__main__":
    main()
