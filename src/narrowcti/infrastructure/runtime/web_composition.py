"""Composition for the Web role's read-only configured source providers."""

from __future__ import annotations

from pathlib import Path

from narrowcti.adapters.sources.misp.explorer import MISPSourceExplorer
from narrowcti.adapters.sources.otx.explorer import OTXSourceExplorer
from narrowcti.application.source_explorer import SourceExplorerService
from narrowcti.infrastructure.config.web_settings import SourceExplorerSettings


def _read_credential(path: str) -> str | None:
    if not path:
        return None
    try:
        with Path(path).open("r", encoding="utf-8") as file_obj:
            value = file_obj.read(8193)
    except (OSError, UnicodeError):
        return None
    if len(value) > 8192:
        return None
    value = value.strip()
    return value or None


def build_source_explorer(settings: SourceExplorerSettings) -> SourceExplorerService:
    """Create providers lazily disabled when their independent credentials are absent."""
    misp = MISPSourceExplorer(
        settings.misp_url,
        _read_credential(settings.misp_key_file),
        verify_tls=settings.misp_verify_tls,
        max_response_bytes=settings.max_response_bytes,
    )
    otx = OTXSourceExplorer(
        _read_credential(settings.otx_key_file),
        max_response_bytes=settings.max_response_bytes,
    )
    return SourceExplorerService((misp, otx))


__all__ = ["build_source_explorer"]
