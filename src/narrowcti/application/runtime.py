"""Scheduler-neutral, single-cycle gateway runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from core.decision_audit import utc_now
from narrowcti.application.provider_registry import SourceRegistry


SUMMARY_FIELDS = (
    "reviewed",
    "ingested",
    "dropped",
    "quarantined",
    "skipped",
    "errors",
    "dry_run",
)


@dataclass(frozen=True)
class SourceRunResult:
    source_key: str
    source_name: str
    success: bool
    summaries: tuple = field(default_factory=tuple)
    error: str = ""

    def total(self, field_name):
        return sum(getattr(summary, field_name, 0) for summary in self.summaries)

    def to_dict(self):
        return {
            "source_key": self.source_key,
            "source_name": self.source_name,
            "success": self.success,
            "error": self.error,
            "summary_count": len(self.summaries),
            "totals": summary_totals(self),
            "summaries": [run_summary_to_dict(summary) for summary in self.summaries],
        }


@dataclass(frozen=True)
class GatewayRunSummary:
    results: tuple[SourceRunResult, ...]
    recorded_at: str = field(default_factory=utc_now)

    @property
    def succeeded(self):
        return sum(1 for result in self.results if result.success)

    @property
    def failed(self):
        return sum(1 for result in self.results if not result.success)

    def total(self, field_name):
        return sum(result.total(field_name) for result in self.results)

    def to_dict(self):
        return {
            "recorded_at": self.recorded_at,
            "sources": len(self.results),
            "succeeded": self.succeeded,
            "failed": self.failed,
            "totals": summary_totals(self),
            "results": [result.to_dict() for result in self.results],
        }


def execute_source(definition, logger):
    logger(f"Gateway source start: {definition.key}")
    try:
        runner = definition.factory()
        summaries = tuple(runner.run_once() or ())
    except Exception as exc:
        logger(f"Gateway source failed: {definition.key} error={exc}")
        return SourceRunResult(
            source_key=definition.key,
            source_name=definition.name,
            success=False,
            error=str(exc),
        )

    logger(
        f"Gateway source complete: {definition.key} "
        f"summaries={len(summaries)} "
        f"reviewed={sum(getattr(summary, 'reviewed', 0) for summary in summaries)} "
        f"ingested={sum(getattr(summary, 'ingested', 0) for summary in summaries)} "
        f"errors={sum(getattr(summary, 'errors', 0) for summary in summaries)}"
    )
    return SourceRunResult(
        source_key=definition.key,
        source_name=definition.name,
        success=True,
        summaries=summaries,
    )


def run_gateway_once(settings, registry: SourceRegistry, logger, summary_sink=None):
    results = []
    for source_key in settings.enabled_sources:
        try:
            definition = registry.get(source_key)
        except KeyError as exc:
            normalized_key = str(source_key).strip().lower()
            logger(f"Gateway source failed: {normalized_key} error={exc}")
            results.append(
                SourceRunResult(
                    source_key=normalized_key,
                    source_name=normalized_key,
                    success=False,
                    error=str(exc),
                )
            )
            continue
        results.append(execute_source(definition, logger))

    summary = GatewayRunSummary(tuple(results))
    log_gateway_summary(summary, logger)
    if summary_sink is not None:
        try:
            summary_sink(summary)
        except Exception as exc:
            # Summary persistence is operationally non-fatal. Concrete sinks
            # retain responsibility for logging the historical error detail.
            logger(f"Gateway summary sink failed: {exc}")
    return summary


def log_gateway_summary(summary, logger):
    totals = " ".join(
        f"{field_name}={summary.total(field_name)}" for field_name in SUMMARY_FIELDS
    )
    logger(
        f"Gateway summary: sources={len(summary.results)} "
        f"succeeded={summary.succeeded} failed={summary.failed} {totals}"
    )


def summary_totals(summary):
    return {field_name: summary.total(field_name) for field_name in SUMMARY_FIELDS}


def run_summary_to_dict(summary):
    data = {
        "query": getattr(summary, "query", ""),
        "available": getattr(summary, "available", 0),
        "handled": getattr(summary, "handled", 0),
    }
    data.update(
        {field_name: getattr(summary, field_name, 0) for field_name in SUMMARY_FIELDS}
    )
    source = getattr(summary, "source", None)
    if source:
        data["source"] = {
            "key": source.key,
            "name": source.name,
            "provider": source.provider,
            "type": source.source_type,
        }
    return data


__all__ = [
    "SUMMARY_FIELDS",
    "SourceRunResult",
    "GatewayRunSummary",
    "execute_source",
    "run_gateway_once",
    "log_gateway_summary",
    "summary_totals",
    "run_summary_to_dict",
]
