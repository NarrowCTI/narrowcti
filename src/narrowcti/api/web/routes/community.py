"""Read-only Community information architecture routes."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from narrowcti.application.capabilities import COMMUNITY_CAPABILITY_NAMES
from narrowcti.application.reporting.web_assurance import (
    project_web_operational_validation,
    project_web_preflight,
)


def register_community_routes(
    app,
    *,
    current_session,
    require_permission,
    require_capability,
    template_context,
    template_response,
    build_operational_reports,
):
    """Register additive Community pages without moving existing route behavior."""

    def authorized(request: Request, capability: str, permission: str | None = None):
        require_capability(capability)
        _session_id, session = current_session(request)
        if permission:
            session = require_permission(session, permission)
        elif not session or not session.principal:
            return None
        return session

    def current_reports():
        try:
            preflight, validation = build_operational_reports(app.state.evidence_service)
        except Exception:
            return None, None
        return preflight, validation

    @app.get("/sources", response_class=HTMLResponse)
    def sources_page(request: Request):
        session = authorized(request, "source.explorer", "source:explore")
        providers = app.state.source_explorer.providers()
        return template_response(
            "community_sources.html",
            template_context(request, session, providers=providers, current_page="/sources"),
        )

    @app.get("/decisions", response_class=HTMLResponse)
    def decisions_page(request: Request):
        session = authorized(request, "reporting.operational", "review:read")
        service = app.state.evidence_service
        records = []
        status = "unavailable"
        if service and service.available:
            try:
                records = service.recent(100)
                status = "available" if records else "no_records"
            except Exception:
                status = "error"
        return template_response(
            "decisions.html",
            template_context(request, session, records=records, evidence_status=status),
        )

    @app.get("/evidence/operational", response_class=HTMLResponse)
    def operational_evidence_page(request: Request):
        session = authorized(request, "reporting.operational", "review:read")
        preflight, _validation = current_reports()
        return template_response(
            "operational_evidence.html",
            template_context(request, session, preflight=project_web_preflight(preflight)),
        )

    @app.get("/evidence/validation", response_class=HTMLResponse)
    def validation_page(request: Request):
        session = authorized(request, "reporting.operational_validation", "review:read")
        _preflight, validation = current_reports()
        return template_response(
            "validation.html",
            template_context(
                request,
                session,
                validation=project_web_operational_validation(validation),
            ),
        )

    @app.get("/system/health", response_class=HTMLResponse)
    def health_page(request: Request):
        session = authorized(request, "ui.basic")
        if session is None:
            return RedirectResponse("/login", status_code=303)
        preflight, _validation = current_reports()
        return template_response(
            "system_health.html",
            template_context(request, session, preflight=project_web_preflight(preflight)),
        )

    @app.get("/system/providers", response_class=HTMLResponse)
    def providers_page(request: Request):
        session = authorized(request, "ui.basic")
        if session is None:
            return RedirectResponse("/login", status_code=303)
        return template_response(
            "system_providers.html",
            template_context(request, session, providers=app.state.source_explorer.providers()),
        )

    @app.get("/system/capabilities", response_class=HTMLResponse)
    def capabilities_page(request: Request):
        session = authorized(request, "ui.basic")
        if session is None:
            return RedirectResponse("/login", status_code=303)
        enabled = app.state.enabled_capabilities
        capabilities = [
            {"name": name, "enabled": bool(enabled.get(name, False))}
            for name in COMMUNITY_CAPABILITY_NAMES
        ]
        return template_response(
            "system_capabilities.html",
            template_context(request, session, community_capabilities=capabilities),
        )


__all__ = ["register_community_routes"]
