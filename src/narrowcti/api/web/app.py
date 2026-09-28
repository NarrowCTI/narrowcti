"""Server-rendered Community UI, Source Explorer, and preserved bearer API."""

from __future__ import annotations

import hmac
import re
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import BoundedSemaphore, Lock
from urllib.parse import parse_qs, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from narrowcti.api.review.app import create_app as create_review_api_app
from narrowcti.api.review.app import load_review_api_settings
from narrowcti.api.review.auth import ReviewCredentialStore
from narrowcti.adapters.entitlements.community import CommunityEntitlements
from narrowcti.ports.jobs import QUARANTINE_EXPORT_JOB, quarantine_export_idempotency_key
from narrowcti.application.capabilities import (
    COMMUNITY_CAPABILITY_NAMES,
    COMMUNITY_FUTURE_CAPABILITIES,
    CapabilityRegistry,
)
from narrowcti.application.source_explorer import SourceExplorerService
from narrowcti.infrastructure.config.web_settings import WebSettings, load_web_settings
from narrowcti.infrastructure.runtime.web_composition import build_source_explorer
from narrowcti.ports.jobs import ActiveJobLimitReached, INGESTION_DRY_RUN_JOB, INGESTION_PREVIEW_JOB, INGESTION_RUN_ONCE_JOB
from narrowcti.ports.source_explorer import ExplorerError, ExplorerSearchRequest
from narrowcti.domain.review.quarantine import released_indicators

from .middleware import RequestBodyLimitMiddleware, SecurityHeadersMiddleware
from .sessions import InMemoryWebSessionStore, WebSession


SESSION_COOKIE_SECURE = "__Host-narrowcti_session"
SESSION_COOKIE_LOCAL = "narrowcti_session"
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_JOB_TYPES = {
    "preview": INGESTION_PREVIEW_JOB,
    "dry-run": INGESTION_DRY_RUN_JOB,
    "run-once": INGESTION_RUN_ONCE_JOB,
}
_FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_PUBLIC_JOB_ERRORS = frozenset({
    "execution_ambiguous",
    "provider_unavailable",
    "candidate_changed",
    "invalid_job",
    "ingestion_failed",
})
_TEMPLATES = Environment(
    loader=FileSystemLoader(str(Path(__file__).with_name("templates"))),
    autoescape=select_autoescape(("html", "xml")),
)


def _form_values(body: bytes) -> dict[str, str]:
    try:
        parsed = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=100,
        )
    except (UnicodeDecodeError, ValueError):
        return {}
    return {key: values[-1] for key, values in parsed.items() if values}


def _same_origin(request: Request, origin: str, public_origin: str = "") -> bool:
    expected = public_origin or f"{request.url.scheme}://{request.url.netloc}"
    supplied = urlsplit(origin)
    trusted = urlsplit(expected)
    return (
        supplied.scheme.lower() == trusted.scheme.lower()
        and supplied.netloc.lower() == trusted.netloc.lower()
        and not supplied.path
        and not supplied.query
        and not supplied.fragment
    )


def _asset_brand_root() -> Path:
    packaged = Path(__file__).with_name("static") / "brand"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[4] / "docs" / "assets" / "brand"


def _template_context(request: Request, session: WebSession | None, **extra):
    return {
        "request": request,
        "principal": session.principal if session else None,
        "csrf_token": session.csrf_token if session else "",
        "capabilities": getattr(request.app.state, "enabled_capabilities", {}),
        **extra,
    }


def _template_response(name: str, context: dict, *, status_code: int = 200) -> HTMLResponse:
    rendered = _TEMPLATES.get_template(name).render(**context)
    return HTMLResponse(rendered, status_code=status_code)


def _bounded_provider_call(semaphore, callback, *args):
    with semaphore:
        return callback(*args)


def _safe_job_result(value):
    if not isinstance(value, dict):
        return {}
    allowed = {
        "action", "source_key", "external_id", "reviewed", "ingested",
        "dropped", "quarantined", "skipped", "errors", "dry_run",
    }
    projected = {
        key: item[:512] if isinstance(item, str) else item
        for key, item in value.items()
        if key in allowed and isinstance(item, (str, int, bool, type(None)))
    }
    items = value.get("items")
    if isinstance(items, list):
        item_keys = {
            "action", "quarantine_id", "external_id", "dry_run",
            "exported_indicator_count", "dedup_duplicate_count", "reason",
        }
        projected["items"] = [
            {
                key: item[:512] if isinstance(item, str) else item
                for key, item in row.items()
                if key in item_keys and isinstance(item, (str, int, bool, type(None)))
            }
            for row in items[:20]
            if isinstance(row, dict)
        ]
    return projected


def _safe_job_error(value) -> str:
    """Expose stable codes only; never render provider/exception messages."""
    code = str(value or "")
    return code if code in _PUBLIC_JOB_ERRORS else ("job_failed" if code else "")


def create_web_app(
    settings: WebSettings | None = None,
    *,
    source_explorer: SourceExplorerService | None = None,
    credential_store: ReviewCredentialStore | None = None,
    review_api_app=None,
    session_store: InMemoryWebSessionStore | None = None,
    job_repository=None,
):
    """Create the Web role without changing the existing bearer API contract."""
    settings = settings or load_web_settings()
    credential_store = credential_store or ReviewCredentialStore.from_file(settings.credentials_file)
    source_explorer = source_explorer or build_source_explorer(settings.sources)
    session_store = session_store or InMemoryWebSessionStore(
        settings.session_idle_seconds,
        settings.session_absolute_seconds,
    )
    cookie_name = SESSION_COOKIE_SECURE if settings.cookie_secure else SESSION_COOKIE_LOCAL

    if review_api_app is None:
        review_api_app = create_review_api_app(settings=load_review_api_settings())
    job_repository = job_repository or getattr(
        getattr(review_api_app, "state", None), "job_repository", None
    )

    app = FastAPI(title="NarrowCTI Community Web", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.session_store = session_store
    app.state.source_explorer = source_explorer
    app.state.job_repository = job_repository
    app.state.review_service = getattr(
        getattr(review_api_app, "state", None), "review_service", None
    )
    capability_registry = CapabilityRegistry.default()
    capability_state = capability_registry.resolve(
        implemented=(*COMMUNITY_CAPABILITY_NAMES, *COMMUNITY_FUTURE_CAPABILITIES),
        entitled=CommunityEntitlements().granted_capabilities(),
    )
    app.state.enabled_capabilities = {
        name: name in capability_state.enabled for name in capability_state.known
    }
    request_rate_lock = Lock()
    request_times: dict[str, deque[float]] = defaultdict(deque)
    provider_semaphores = defaultdict(lambda: BoundedSemaphore(1))

    async def require_csrf(request: Request):
        if request.method not in _UNSAFE_METHODS:
            return
        origin = request.headers.get("origin")
        if origin and not _same_origin(request, origin, settings.public_origin):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        session_id = request.cookies.get(cookie_name)
        session = session_store.get(session_id)
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        values = (
            _form_values(await request.body())
            if content_type == "application/x-www-form-urlencoded"
            else {}
        )
        supplied = request.headers.get("x-csrf-token") or values.get("_csrf", "")
        if not session or not supplied or not hmac.compare_digest(session.csrf_token, supplied):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        if content_type != "application/x-www-form-urlencoded":
            raise HTTPException(status_code=415, detail="unsupported browser form encoding")

    def current_session(request: Request) -> tuple[str | None, WebSession | None]:
        session_id = request.cookies.get(cookie_name)
        return session_id, session_store.get(session_id)

    def require_permission(session: WebSession | None, permission: str):
        if not session or not session.principal:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        if not session.principal.has_permission(permission):
            raise HTTPException(status_code=403, detail="permission denied")
        return session

    def require_capability(name: str):
        if not app.state.enabled_capabilities.get(name, False):
            raise HTTPException(status_code=404, detail="feature unavailable")

    def allow_rate_limited_request(session_id: str, *, limit: int = 10, interval: int = 60):
        now = time.monotonic()
        with request_rate_lock:
            entries = request_times[session_id]
            while entries and now - entries[0] >= interval:
                entries.popleft()
            if len(entries) >= limit:
                raise HTTPException(status_code=429, detail="request rate limit reached")
            entries.append(now)
            if len(request_times) > 10000:
                request_times.pop(next(iter(request_times)))

    def parse_form(request: Request, body: bytes):
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            raise HTTPException(status_code=415, detail="unsupported browser form encoding")
        return _form_values(body)

    async def require_source_explorer_permission(request: Request):
        _session_id, session = current_session(request)
        if not session or not session.principal:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        if not session.principal.has_permission("source:explore"):
            raise HTTPException(status_code=403, detail="permission denied")
        return session

    @app.exception_handler(HTTPException)
    async def browser_http_exception_handler(request: Request, exc: HTTPException):
        if exc.status_code == 303 and exc.headers and exc.headers.get("Location") == "/login":
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(
            str(exc.detail),
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"status": "ok"}

    @app.get("/assets/app.css", include_in_schema=False)
    async def app_css():
        return FileResponse(Path(__file__).with_name("static") / "app.css", media_type="text/css")

    @app.get("/assets/htmx.min.js", include_in_schema=False)
    async def htmx_script():
        return FileResponse(Path(__file__).with_name("static") / "htmx.min.js", media_type="text/javascript")

    @app.get("/assets/brand/{asset_path:path}", include_in_schema=False)
    async def brand_asset(asset_path: str):
        candidate = (_asset_brand_root() / Path(*Path(asset_path).parts)).resolve()
        root = _asset_brand_root().resolve()
        if root not in candidate.parents or not candidate.is_file():
            raise HTTPException(status_code=404, detail="asset not found")
        return FileResponse(candidate)

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        session_id, session = current_session(request)
        response = RedirectResponse("/", status_code=303) if session and session.principal else None
        if response:
            return response
        if not session:
            session_id, session = session_store.create_anonymous()
        response = _template_response("login.html", _template_context(request, session))
        if session_id and request.cookies.get(cookie_name) != session_id:
            _set_session_cookie(response, cookie_name, session_id, settings)
        return response

    @app.post("/login", dependencies=[Depends(require_csrf)], response_class=HTMLResponse)
    async def login_submit(request: Request):
        old_session_id, session = current_session(request)
        values = parse_form(request, await request.body())
        token = values.get("credential", "")
        principal = credential_store.authenticate(token)
        del token  # Do not retain the submitted bearer token beyond validation.
        values.clear()
        if not principal or not session or session.principal:
            anonymous_id, anonymous = session_store.create_anonymous()
            response = _template_response(
                "login.html",
                _template_context(request, anonymous, error="The supplied credential is invalid."),
                status_code=401,
            )
            _set_session_cookie(response, cookie_name, anonymous_id, settings)
            return response
        session_id, _authenticated = session_store.authenticate(old_session_id or "", principal)
        response = RedirectResponse("/", status_code=303)
        _set_session_cookie(response, cookie_name, session_id, settings)
        return response

    @app.post("/logout", dependencies=[Depends(require_csrf)])
    async def logout(request: Request):
        session_id = request.cookies.get(cookie_name)
        session_store.delete(session_id)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(cookie_name, path="/", secure=settings.cookie_secure, httponly=True, samesite="lax")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        require_capability("ui.basic")
        _session_id, session = current_session(request)
        if not session or not session.principal:
            return RedirectResponse("/login", status_code=303)
        return _template_response(
            "home.html",
            _template_context(request, session, providers=source_explorer.providers()),
        )

    @app.get("/review", response_class=HTMLResponse)
    async def review_page(request: Request, status: str = "pending"):
        _session_id, session = current_session(request)
        require_permission(session, "review:read")
        if app.state.review_service is None:
            raise HTTPException(status_code=503, detail="review service is unavailable")
        if status not in {"all", "pending", "released", "partially-released", "rejected", "expired"}:
            raise HTTPException(status_code=400, detail="invalid review status")
        records = app.state.review_service.list_records(status=status, limit=100)
        projected = [
            {
                "quarantine_id": str(item.get("quarantine_id", "")),
                "title": str(item.get("title", ""))[:512],
                "source_key": str(item.get("source_key", ""))[:64],
                "external_id": str(item.get("external_id", ""))[:256],
                "reason": str(item.get("reason", ""))[:512],
                "status": str(item.get("status", ""))[:32],
                "indicator_count": int(item.get("indicator_count", 0) or 0),
                "created_at": str(item.get("created_at", ""))[:64],
            }
            for item in records
        ]
        return _template_response(
            "review.html",
            _template_context(request, session, records=projected, status=status),
        )

    @app.post("/review/records/{quarantine_id}/{action}", dependencies=[Depends(require_csrf)])
    async def review_action(request: Request, quarantine_id: str, action: str):
        _session_id, session = current_session(request)
        values = parse_form(request, await request.body())
        reason = values.get("reason", "")[:2000]
        if app.state.review_service is None:
            raise HTTPException(status_code=503, detail="review service is unavailable")
        if action in {"release", "reject"}:
            session = require_permission(session, "review:decide")
            operation = getattr(app.state.review_service, action)
            operation(quarantine_id, reason, reviewer=session.principal.principal)
            return RedirectResponse("/review", status_code=303)
        if action == "export-preview":
            session = require_permission(session, "export:preview")
            items = app.state.review_service.export_released(quarantine_id, dry_run=True)
            return _template_response(
                "review_result.html",
                _template_context(
                    request,
                    session,
                    title="Export preview",
                    items=[
                        {
                            key: value
                            for key, value in item.to_dict().items()
                            if key in {
                                "action", "quarantine_id", "external_id", "dry_run",
                                "exported_indicator_count", "dedup_duplicate_count", "reason",
                            }
                            and isinstance(value, (str, int, bool, type(None)))
                        }
                        for item in items[:20]
                    ],
                ),
            )
        if action == "export":
            session = require_permission(session, "export:execute")
            if job_repository is None:
                raise HTTPException(status_code=503, detail="Worker job queue is unavailable")
            record = app.state.review_service.get_record(quarantine_id)
            review_settings = getattr(getattr(review_api_app, "state", None), "settings", None)
            job = job_repository.submit(
                QUARANTINE_EXPORT_JOB,
                "web-review",
                {
                    "quarantine_id": quarantine_id,
                    "identity_name": getattr(review_settings, "identity_name", "NarrowCTI Gateway"),
                    "exported_by": f"web-review:{session.principal.principal}",
                    "requester": session.principal.principal,
                },
                idempotency_key=quarantine_export_idempotency_key(
                    quarantine_id,
                    released_indicators(record),
                ),
            )
            if job.get("status") == "failed":
                job = job_repository.retry_failed(job["job_id"])
            return RedirectResponse(f"/jobs/{job['job_id']}", status_code=303)
        raise HTTPException(status_code=404, detail="review operation not found")

    @app.get("/explorer", response_class=HTMLResponse, dependencies=[Depends(require_source_explorer_permission)])
    async def sources_page(request: Request):
        require_capability("source.explorer")
        _session_id, session = current_session(request)
        return _template_response(
            "sources.html",
            _template_context(request, session, providers=source_explorer.providers()),
        )

    @app.post(
        "/explorer/search",
        dependencies=[Depends(require_csrf), Depends(require_source_explorer_permission)],
        response_class=HTMLResponse,
    )
    async def source_search(request: Request):
        session_id, session = current_session(request)
        require_capability("source.explorer")
        values = parse_form(request, await request.body())
        provider_key = values.get("provider_key", "")
        if provider_key not in {item.key for item in source_explorer.providers()}:
            raise HTTPException(status_code=404, detail="provider not found")
        allow_rate_limited_request(session_id or "")
        filters = {}
        tag = values.get("tag", "").strip()
        if tag and provider_key == "misp":
            filters["tag"] = (tag,)
        try:
            def execute_search():
                with provider_semaphores[provider_key]:
                    return source_explorer.search(
                        ExplorerSearchRequest(
                            provider_key=provider_key,
                            query=values.get("query", ""),
                            filters=filters,
                            limit=10,
                        )
                    )

            result = await run_in_threadpool(execute_search)
            context = _template_context(request, session, result=result, error=None)
        except ExplorerError as exc:
            context = _template_context(
                request,
                session,
                result=None,
                error={"code": exc.code, "message": exc.public_message},
            )
        if request.headers.get("hx-request", "").lower() == "true":
            return _template_response("search_results.html", context)
        return _template_response(
            "sources.html",
            {**context, "providers": source_explorer.providers(), "initial_result": True},
        )

    @app.get("/explorer/{provider_key}/{external_id}", response_class=HTMLResponse)
    async def source_detail(
        request: Request,
        provider_key: str,
        external_id: str,
    ):
        session_id, session = current_session(request)
        require_capability("source.explorer")
        require_permission(session, "source:explore")
        if provider_key not in {item.key for item in source_explorer.providers()}:
            raise HTTPException(status_code=404, detail="provider not found")
        allow_rate_limited_request(session_id or "")
        try:
            item = await run_in_threadpool(
                lambda: _bounded_provider_call(
                    provider_semaphores[provider_key],
                    source_explorer.detail,
                    provider_key,
                    external_id,
                )
            )
        except ExplorerError as exc:
            raise HTTPException(status_code=404 if exc.code == "source_not_found" else 503, detail=exc.public_message) from None
        return _template_response(
            "source_detail.html",
            _template_context(request, session, item=item, request_id=secrets.token_urlsafe(18)),
        )

    @app.post("/explorer/{provider_key}/{external_id}/{mode}", dependencies=[Depends(require_csrf)])
    async def submit_ingestion_job(request: Request, provider_key: str, external_id: str, mode: str):
        _session_id, session = current_session(request)
        if mode not in _JOB_TYPES or provider_key not in {"misp", "otx"}:
            raise HTTPException(status_code=404, detail="operation not found")
        require_capability("ingestion.run_once" if mode == "run-once" else "source.explorer")
        permission = {
            "preview": "ingestion:preview",
            "dry-run": "ingestion:dry_run",
            "run-once": "ingestion:run",
        }[mode]
        session = require_permission(session, permission)
        values = parse_form(request, await request.body())
        request_id = values.get("request_id", "")
        fingerprint = values.get("expected_fingerprint", "")
        if not _REQUEST_ID.fullmatch(request_id) or not _FINGERPRINT.fullmatch(fingerprint):
            raise HTTPException(status_code=400, detail="invalid source revision identity")
        if not external_id or len(external_id) > 256 or any(ord(char) < 32 for char in external_id):
            raise HTTPException(status_code=400, detail="invalid source identifier")
        if job_repository is None:
            raise HTTPException(status_code=503, detail="Worker job queue is unavailable")
        job_type = _JOB_TYPES[mode]
        payload = {
            "source_key": provider_key,
            "external_id": external_id,
            "expected_fingerprint": fingerprint,
            "request_id": request_id,
            "requester": session.principal.principal,
        }
        idempotency_key = f"{job_type}:{session.principal.credential_id}:{request_id}"
        active_limit = 1 if mode == "run-once" else 3
        try:
            job = job_repository.submit(
                job_type,
                provider_key,
                payload,
                idempotency_key=idempotency_key,
                active_limit=active_limit,
            )
        except ActiveJobLimitReached:
            raise HTTPException(status_code=429, detail="active job limit reached") from None
        return RedirectResponse(f"/jobs/{job['job_id']}", status_code=303)

    def visible_job(request: Request, job_id: str):
        _session_id, session = current_session(request)
        session = require_permission(session, "review:read")
        if job_repository is None:
            raise HTTPException(status_code=503, detail="Worker job queue is unavailable")
        job = job_repository.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        payload = job.get("payload") or {}
        requester = payload.get("requester") or str(payload.get("exported_by", "")).rsplit(":", 1)[-1]
        if requester != session.principal.principal and not session.principal.has_permission("*"):
            raise HTTPException(status_code=404, detail="job not found")
        projected = {
            "job_id": str(job.get("job_id", "")),
            "job_type": str(job.get("job_type", "")),
            "status": str(job.get("status", "")),
            "created_at": str(job.get("created_at", "")),
            "error": _safe_job_error(job.get("error")),
            "result": _safe_job_result(job.get("result")),
        }
        return session, projected

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_status(request: Request, job_id: str):
        session, projected = visible_job(request, job_id)
        return _template_response("job_status.html", _template_context(request, session, job=projected))

    @app.get("/jobs/{job_id}/status", response_class=HTMLResponse)
    async def job_status_fragment(request: Request, job_id: str):
        session, projected = visible_job(request, job_id)
        return _template_response(
            "job_status_fragment.html",
            _template_context(request, session, job=projected),
        )

    # The established Review API remains a separate bearer-authenticated ASGI app.
    app.mount("/", review_api_app, name="review-api")

    secured = RequestBodyLimitMiddleware(app, settings.max_request_body_bytes)
    trusted = TrustedHostMiddleware(secured, allowed_hosts=list(settings.allowed_hosts))
    return SecurityHeadersMiddleware(trusted, secure_cookies=settings.cookie_secure)


def _set_session_cookie(response, cookie_name: str, session_id: str, settings: WebSettings) -> None:
    response.set_cookie(
        cookie_name,
        session_id,
        max_age=settings.session_absolute_seconds,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )


__all__ = ["SESSION_COOKIE_LOCAL", "SESSION_COOKIE_SECURE", "create_web_app"]
