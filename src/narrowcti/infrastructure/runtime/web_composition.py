"""Composition for the Web role's read-only configured source providers."""

from __future__ import annotations

from pathlib import Path

from narrowcti.adapters.sources.misp.explorer import MISPSourceExplorer
from narrowcti.adapters.sources.otx.explorer import OTXSourceExplorer
from narrowcti.adapters.persistence.local.web_evidence_reader import read_recent_records
from narrowcti.adapters.persistence.local.operator_store import LocalOperatorStore
from narrowcti.application.identity.passwords import LocalOperatorAuthenticator, PasswordService
from narrowcti.application.source_explorer import SourceExplorerService
from narrowcti.application.reporting.web_evidence import WebEvidenceService
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


def build_web_evidence(settings) -> WebEvidenceService:
    """Expose bounded decision evidence from the configured local audit directory."""
    directory = str(getattr(settings, "decision_audit_dir", "") or "")
    reader = (lambda limit: read_recent_records(directory, limit)) if directory else None
    return WebEvidenceService(reader)


def build_operator_authentication(settings):
    """Compose local operator persistence and password authentication for Web."""
    store = LocalOperatorStore(settings.auth_db)
    return store, LocalOperatorAuthenticator(store, PasswordService())


__all__ = ["build_operator_authentication", "build_source_explorer", "build_web_evidence"]
