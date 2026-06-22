import time
from dataclasses import dataclass, field
from typing import Callable, Iterable


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
class SourceDefinition:
    key: str
    name: str
    factory: Callable[[], object]


@dataclass(frozen=True)
class SourceRunResult:
    source_key: str
    source_name: str
    success: bool
    summaries: tuple = field(default_factory=tuple)
    error: str = ""

    def total(self, field_name):
        return sum(getattr(summary, field_name, 0) for summary in self.summaries)


@dataclass(frozen=True)
class GatewayRunSummary:
    results: tuple[SourceRunResult, ...]

    @property
    def succeeded(self):
        return sum(1 for result in self.results if result.success)

    @property
    def failed(self):
        return sum(1 for result in self.results if not result.success)

    def total(self, field_name):
        return sum(result.total(field_name) for result in self.results)


class SourceRegistry:
    def __init__(self, definitions: Iterable[SourceDefinition] | None = None):
        self._definitions = {}
        for definition in definitions or ():
            self.register(definition.key, definition.name, definition.factory)

    def register(self, key, name, factory):
        normalized_key = normalize_source_key(key)
        if normalized_key in self._definitions:
            raise ValueError(f"Source already registered: {normalized_key}")

        self._definitions[normalized_key] = SourceDefinition(
            key=normalized_key,
            name=name,
            factory=factory,
        )
        return self

    def get(self, key):
        normalized_key = normalize_source_key(key)
        if normalized_key not in self._definitions:
            raise KeyError(f"Unknown source: {normalized_key}")
        return self._definitions[normalized_key]

    @property
    def source_keys(self):
        return tuple(self._definitions.keys())


def normalize_source_key(value):
    return str(value).strip().lower()


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


def run_gateway_once(settings, registry, logger):
    results = []

    for source_key in settings.enabled_sources:
        try:
            definition = registry.get(source_key)
        except KeyError as exc:
            normalized_key = normalize_source_key(source_key)
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
    return summary


def run_gateway_loop(settings, registry, logger, sleeper=time.sleep):
    while True:
        run_gateway_once(settings, registry, logger)
        logger(f"Gateway sleeping {settings.source_interval_seconds}s")
        sleeper(settings.source_interval_seconds)


def log_gateway_summary(summary, logger):
    totals = " ".join(
        f"{field_name}={summary.total(field_name)}" for field_name in SUMMARY_FIELDS
    )
    logger(
        f"Gateway summary: sources={len(summary.results)} "
        f"succeeded={summary.succeeded} failed={summary.failed} {totals}"
    )
