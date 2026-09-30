"""Read-only Community information architecture routes."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from narrowcti.application.capabilities import (
    COMMUNITY_CAPABILITY_NAMES,
    COMMUNITY_CAPABILITY_PRESENTATION,
)
from narrowcti.application.reporting.operational_snapshot import (
    load_operational_validation_snapshot,
    load_preflight_snapshot,
)
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
    operational_state_reader,
    require_csrf,
    readiness_limiter,
    bounded_provider_call,
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
        preflight_hint = (
            "Ask a Gateway operator to rerun the authoritative preflight workflow. "
            "This Web page is read-only and does not execute it."
        )
        validation_hint = (
            "Ask an operator to rerun Operational Validation from the Gateway/Ops role "
            "with its manual and relationship evidence inputs. This Web page is read-only."
        )
        try:
            raw_preflight = app.state.operational_state_reader.read_preflight()
        except Exception:
            raw_preflight = None
        preflight_snapshot = load_preflight_snapshot(raw_preflight)
        preflight = (
            preflight_snapshot.to_web_dict()
            if preflight_snapshot
            else {
                **project_web_preflight(None),
                "captured_at": None,
                "freshness": "unavailable",
            }
        )
        preflight["refresh_hint"] = preflight_hint

        try:
            raw_validation = app.state.operational_state_reader.read_validation()
        except Exception:
            raw_validation = None
        validation_snapshot = load_operational_validation_snapshot(raw_validation)
        validation = (
            validation_snapshot.to_web_dict()
            if validation_snapshot
            else {
                **project_web_operational_validation(None),
                "captured_at": None,
                "freshness": "unavailable",
                "required_sources": (),
            }
        )
        validation["refresh_hint"] = validation_hint
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
            template_context(request, session, preflight=preflight or project_web_preflight(None)),
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
                validation=validation or project_web_operational_validation(None),
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
            template_context(request, session, preflight=preflight or project_web_preflight(None)),
        )

    @app.get("/system/providers", response_class=HTMLResponse)
    def providers_page(request: Request):
        session = authorized(request, "ui.basic")
        if session is None:
            return RedirectResponse("/login", status_code=303)
        return template_response(
            "system_providers.html",
            template_context(request, session, providers=app.state.source_explorer.providers(), readiness=None),
        )

    @app.post(
        "/system/providers/{provider_key}/readiness",
        dependencies=[Depends(require_csrf)],
        response_class=HTMLResponse,
    )
    async def provider_readiness_page(request: Request, provider_key: str):
        session = authorized(request, "ui.basic")
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not readiness_limiter.allow(
            f"provider-readiness:{session.principal.operator_id}",
            limit=3,
            interval=60,
        ):
            raise HTTPException(status_code=429, detail="provider readiness rate limit reached")
        try:
            readiness = await bounded_provider_call(
                provider_key,
                app.state.source_explorer.check_readiness,
                provider_key,
            )
        except Exception as exc:
            if getattr(exc, "code", "") == "provider_unknown":
                raise HTTPException(status_code=404, detail="provider readiness is unavailable") from None
            raise
        return template_response(
            "system_providers.html",
            template_context(
                request,
                session,
                providers=app.state.source_explorer.providers(),
                readiness=readiness,
            ),
        )

    @app.get("/system/capabilities", response_class=HTMLResponse)
    def capabilities_page(request: Request):
        session = authorized(request, "ui.basic")
        if session is None:
            return RedirectResponse("/login", status_code=303)
        enabled = app.state.enabled_capabilities
        capabilities = [
            {
                "id": name,
                "label": COMMUNITY_CAPABILITY_PRESENTATION[name][0],
                "description": COMMUNITY_CAPABILITY_PRESENTATION[name][1],
                "enabled": bool(enabled.get(name, False)),
            }
            for name in COMMUNITY_CAPABILITY_NAMES
        ]
        return template_response(
            "system_capabilities.html",
            template_context(request, session, community_capabilities=capabilities),
        )


__all__ = ["register_community_routes"]
