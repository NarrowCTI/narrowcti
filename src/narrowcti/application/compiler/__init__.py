"""Source-neutral compilation contracts for export boundaries."""

from .contracts import (
    CompilationResult,
    ObjectSemantics,
    RelationshipSemantics,
    ReportContext,
)
from .graph import compile_graph_semantics

__all__ = [
    "CompilationResult",
    "ObjectSemantics",
    "RelationshipSemantics",
    "ReportContext",
    "compile_graph_semantics",
]
