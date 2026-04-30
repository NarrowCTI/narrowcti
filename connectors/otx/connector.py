import time
from pycti import OpenCTIApiClient

from otx_client import OTXClient
from processor import OTXProcessor
from settings import load_settings


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def build_processor(settings):
    api = OpenCTIApiClient(settings.opencti_url, settings.opencti_token)
    otx = OTXClient(
        settings.otx_api_key,
        search_timeout=settings.otx_search_timeout,
        enrich_timeout=settings.otx_timeout,
        retries=settings.otx_retries,
        retry_backoff_seconds=settings.otx_retry_backoff_seconds,
        logger=log,
    )
    return OTXProcessor(settings, otx, api, log)


def main():
    settings = load_settings()
    processor = build_processor(settings)

    while True:
        processor.run_once()
        log(f"Sleeping {settings.connector_run_interval}s")
        time.sleep(settings.connector_run_interval)


if __name__ == "__main__":
    main()
