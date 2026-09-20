"""Compatibility runtime preserving the historical gateway signatures."""

from __future__ import annotations

import time

from narrowcti.application.provider_registry import SourceDefinition, SourceRegistry, normalize_source_key
from narrowcti.application.runtime import (
    SUMMARY_FIELDS,
    GatewayRunSummary,
    SourceRunResult,
    execute_source,
    log_gateway_summary,
    run_summary_to_dict,
    summary_totals,
)
from narrowcti.application.runtime import run_gateway_once as _run_gateway_once
from narrowcti.cli.gateway import run_gateway_loop as _run_gateway_loop
from narrowcti.infrastructure.runtime.summary_store import write_gateway_summary


def run_gateway_once(settings, registry, logger):
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
    return _run_gateway_loop(settings, registry, logger, sleeper=sleeper)


__all__ = [
    "SUMMARY_FIELDS", "SourceDefinition", "SourceRegistry", "SourceRunResult",
    "GatewayRunSummary", "normalize_source_key", "execute_source", "run_gateway_once",
    "run_gateway_loop", "log_gateway_summary", "summary_totals", "run_summary_to_dict",
    "write_gateway_summary",
]
