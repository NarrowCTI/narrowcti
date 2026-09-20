"""Compatibility surface for concrete Community source composition."""

from narrowcti.infrastructure.runtime.gateway_composition import (
    SOURCE_RUNTIME_PATHS,
    ProcessorRunner,
    apply_gateway_source_paths,
    build_artifact_dedup,
    build_misp_runner,
    build_otx_runner,
    build_source_dedup,
    default_source_registry,
    gateway_file,
)

__all__ = [
    "SOURCE_RUNTIME_PATHS", "ProcessorRunner", "apply_gateway_source_paths",
    "build_artifact_dedup", "build_misp_runner", "build_otx_runner",
    "build_source_dedup", "default_source_registry", "gateway_file",
]
