import time


def run_processor_loop(processor, settings, logger, sleeper=time.sleep):
    while True:
        processor.run_once()
        logger(f"Sleeping {settings.connector_run_interval}s")
        sleeper(settings.connector_run_interval)
