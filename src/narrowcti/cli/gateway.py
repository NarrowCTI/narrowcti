"""Community gateway composition root and scheduler boundary."""

from __future__ import annotations

import time

from narrowcti.application.runtime import run_gateway_once as _run_gateway_once
from narrowcti.infrastructure.config.settings import load_settings
from narrowcti.infrastructure.runtime.gateway_composition import default_source_registry
from narrowcti.infrastructure.runtime.summary_store import write_gateway_summary


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def _run_once(settings, registry, logger):
    return _run_gateway_once(
        settings,
        registry,
        logger,
        summary_sink=lambda summary: write_gateway_summary(
            summary,
            getattr(settings, "run_summary_file", ""),
            logger,
        ),
    )


def run_gateway_loop(settings, registry, logger, sleeper=time.sleep):
    while True:
        _run_once(settings, registry, logger)
        logger(f"Gateway sleeping {settings.source_interval_seconds}s")
        sleeper(settings.source_interval_seconds)


def main():
    settings = load_settings()
    registry = default_source_registry(log, settings)
    if settings.run_once:
        _run_once(settings, registry, log)
        return
    run_gateway_loop(settings, registry, log)


__all__ = ["log", "run_gateway_loop", "main"]

