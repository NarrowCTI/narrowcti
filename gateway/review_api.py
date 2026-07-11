import os
from dataclasses import dataclass
from threading import RLock
from typing import Annotated, Literal

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.deduplication import ArtifactDeduplicationIndex
from core.opencti_deduplication import (
    CompositeArtifactDeduplication,
    OpenCTIArtifactLookup,
)
from gateway.opencti_client import build_opencti_client
from gateway.review import AnalystReviewService
from gateway.review_auth import ReviewCredentialStore, ReviewPrincipal


ReviewStatus = Literal[
    "all",
    "pending",
    "released",
    "partially-released",
    "rejected",
    "expired",
]


@dataclass(frozen=True)
class ReviewApiSettings:
    repository_file: str
    release_audit_file: str
    credentials_file: str
    host: str = "127.0.0.1"
    port: int = 8081
    docs_enabled: bool = False
    allow_export: bool = False
    require_reason: bool = True
    identity_name: str = "NarrowCTI Gateway"
    dedup_state_file: str = ""
    opencti_dedup_lookup: bool = False
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    max_request_body_bytes: int = 16384

    def __post_init__(self):
        if not self.repository_file:
            raise ValueError("review API repository file is required")
        if not self.release_audit_file:
            raise ValueError("review API release audit file is required")
        if not self.credentials_file:
            raise ValueError("review API credentials file is required")
        if self.port < 1 or self.port > 65535:
            raise ValueError("review API port must be between 1 and 65535")
        if not self.allowed_hosts:
            raise ValueError("review API allowed hosts must not be empty")
        if self.max_request_body_bytes < 1024:
            raise ValueError("review API max request body must be at least 1024 bytes")


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError("reason must not be blank")
        return normalized


class PartialReleaseRequest(DecisionRequest):
    indicator_types: list[str] = Field(min_length=1, max_length=50)

    @field_validator("indicator_types")
    @classmethod
    def normalize_indicator_types(cls, values):
        normalized = []
        for value in values:
            item = str(value).strip().lower()
            if not item or len(item) > 64:
                raise ValueError("indicator types must contain 1 to 64 characters")
            if item not in normalized:
                normalized.append(item)
        return normalized


def env_bool(name, default=False, environ=None):
    environ = environ or os.environ
    value = environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in ("true", "1", "yes")


def load_review_api_settings(environ=None):
    environ = environ or os.environ
    state_dir = environ.get("NARROWCTI_STATE_DIR", "/app/state")
    return ReviewApiSettings(
        repository_file=environ.get(
            "NARROWCTI_QUARANTINE_REPOSITORY",
            os.path.join(state_dir, "quarantine.jsonl"),
        ),
        release_audit_file=environ.get(
            "NARROWCTI_RELEASE_AUDIT_FILE",
            os.path.join(state_dir, "audit", "releases.jsonl"),
        ),
        credentials_file=environ.get(
            "NARROWCTI_REVIEW_API_CREDENTIALS_FILE",
            "",
        ),
        host=environ.get("NARROWCTI_REVIEW_API_HOST", "127.0.0.1"),
        port=int(environ.get("NARROWCTI_REVIEW_API_PORT", "8081")),
        docs_enabled=env_bool(
            "NARROWCTI_REVIEW_API_DOCS_ENABLED",
            False,
            environ,
        ),
        allow_export=env_bool(
            "NARROWCTI_REVIEW_API_ALLOW_EXPORT",
            False,
            environ,
        ),
        require_reason=env_bool(
            "NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON",
            True,
            environ,
        ),
        identity_name=environ.get(
            "NARROWCTI_REVIEW_API_IDENTITY_NAME",
            "NarrowCTI Gateway",
        ),
        dedup_state_file=environ.get("NARROWCTI_DEDUP_STATE_FILE", ""),
        opencti_dedup_lookup=env_bool(
            "NARROWCTI_OPENCTI_DEDUP_LOOKUP",
            False,
            environ,
        ),
        allowed_hosts=tuple(
            host.strip()
            for host in environ.get(
                "NARROWCTI_REVIEW_API_ALLOWED_HOSTS",
                "127.0.0.1,localhost,testserver",
            ).split(",")
            if host.strip()
        ),
        max_request_body_bytes=int(
            environ.get("NARROWCTI_REVIEW_API_MAX_BODY_BYTES", "16384")
        ),
    )


def default_opencti_client_factory():
    opencti_url = os.getenv("OPENCTI_URL", "")
    opencti_token = os.getenv("OPENCTI_TOKEN", "")
    if not opencti_url or not opencti_token:
        raise ValueError("OPENCTI_URL and OPENCTI_TOKEN are required for export")
    return build_opencti_client(opencti_url, opencti_token)


def build_export_dedup(settings, api_client):
    local_index = (
        ArtifactDeduplicationIndex(settings.dedup_state_file)
        if settings.dedup_state_file
        else None
    )
    opencti_lookup = (
        OpenCTIArtifactLookup(api_client) if settings.opencti_dedup_lookup else None
    )
    if not local_index and not opencti_lookup:
        return None
    return CompositeArtifactDeduplication(
        local_index=local_index,
        opencti_lookup=opencti_lookup,
    )


def create_app(
    settings=None,
    review_service=None,
    credential_store=None,
    opencti_client_factory=None,
):
    settings = settings or load_review_api_settings()
    credential_store = credential_store or ReviewCredentialStore.from_file(
        settings.credentials_file
    )
    review_service = review_service or AnalystReviewService.from_paths(
        settings.repository_file,
        release_audit_file=settings.release_audit_file,
        require_reason=settings.require_reason,
    )
    opencti_client_factory = (
        opencti_client_factory or default_opencti_client_factory
    )
    repository_lock = RLock()
    docs_url = "/docs" if settings.docs_enabled else None
    openapi_url = "/openapi.json" if settings.docs_enabled else None
    app = FastAPI(
        title="NarrowCTI Analyst Review API",
        version="0.9.0-dev",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )
    app.state.settings = settings
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.allowed_hosts),
    )
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        content_length = request.headers.get("content-length")
        try:
            request_size = int(content_length) if content_length else 0
        except ValueError:
            request_size = -1
        if request_size < 0:
            response = JSONResponse(
                status_code=400,
                content={"detail": "invalid content length"},
            )
        elif request_size > settings.max_request_body_bytes:
            response = JSONResponse(
                status_code=413,
                content={"detail": "request body too large"},
            )
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def authenticated_principal(
        authorization: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer),
        ],
    ):
        principal = None
        if authorization and authorization.scheme.lower() == "bearer":
            principal = credential_store.authenticate(authorization.credentials)
        if not principal:
            raise HTTPException(
                status_code=401,
                detail="invalid or missing bearer credential",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return principal

    def require_permission(permission):
        def dependency(
            principal: Annotated[
                ReviewPrincipal,
                Depends(authenticated_principal),
            ],
        ):
            if not principal.has_permission(permission):
                raise HTTPException(status_code=403, detail="permission denied")
            return principal

        return dependency

    read_principal = require_permission("review:read")
    decision_principal = require_permission("review:decide")
    preview_principal = require_permission("export:preview")
    export_principal = require_permission("export:execute")

    def guarded_transition(callback):
        try:
            with repository_lock:
                return callback()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    def present_record(record, include_raw, principal):
        if include_raw and not principal.has_permission("review:raw"):
            raise HTTPException(status_code=403, detail="raw snapshot access denied")
        presented = dict(record)
        if not include_raw:
            presented.pop("raw_snapshot", None)
        return presented

    def present_results(results):
        return {
            "count": len(results),
            "items": [result.to_dict() for result in results],
        }

    @app.get("/healthz", include_in_schema=False)
    def health():
        return {"status": "ok", "service": "narrowcti-review-api"}

    @app.get("/api/v1/review/summary")
    def summary(
        principal: Annotated[ReviewPrincipal, Depends(read_principal)],
    ):
        del principal
        with repository_lock:
            return review_service.summary().to_dict()

    @app.get("/api/v1/review/records")
    def list_records(
        principal: Annotated[ReviewPrincipal, Depends(read_principal)],
        status: ReviewStatus = "pending",
        source_key: Annotated[str, Query(max_length=128)] = "",
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ):
        del principal
        with repository_lock:
            records = review_service.list_records(
                status=status,
                source_key=source_key,
                limit=limit,
            )
        return {
            "count": len(records),
            "items": [present_record(record, False, None) for record in records],
        }

    @app.get("/api/v1/review/records/{quarantine_id}")
    def get_record(
        quarantine_id: str,
        principal: Annotated[ReviewPrincipal, Depends(read_principal)],
        include_raw: bool = False,
    ):
        record = guarded_transition(lambda: review_service.get_record(quarantine_id))
        return present_record(record, include_raw, principal)

    @app.get("/api/v1/review/audit")
    def audit_events(
        principal: Annotated[ReviewPrincipal, Depends(read_principal)],
        quarantine_id: Annotated[str, Query(max_length=128)] = "",
        action: Annotated[str, Query(max_length=64)] = "",
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ):
        del principal
        with repository_lock:
            events = review_service.audit_events(
                quarantine_id=quarantine_id,
                action=action,
                limit=limit,
            )
        return {"count": len(events), "items": events}

    @app.post("/api/v1/review/records/{quarantine_id}/release")
    def release(
        quarantine_id: str,
        request: DecisionRequest,
        principal: Annotated[ReviewPrincipal, Depends(decision_principal)],
    ):
        return guarded_transition(
            lambda: review_service.release(
                quarantine_id,
                request.reason,
                reviewer=principal.principal,
            )
        )

    @app.post("/api/v1/review/records/{quarantine_id}/release-indicators")
    def release_indicators(
        quarantine_id: str,
        request: PartialReleaseRequest,
        principal: Annotated[ReviewPrincipal, Depends(decision_principal)],
    ):
        return guarded_transition(
            lambda: review_service.release_indicators(
                quarantine_id,
                request.indicator_types,
                request.reason,
                reviewer=principal.principal,
            )
        )

    @app.post("/api/v1/review/records/{quarantine_id}/reject")
    def reject(
        quarantine_id: str,
        request: DecisionRequest,
        principal: Annotated[ReviewPrincipal, Depends(decision_principal)],
    ):
        return guarded_transition(
            lambda: review_service.reject(
                quarantine_id,
                request.reason,
                reviewer=principal.principal,
            )
        )

    @app.post("/api/v1/review/records/{quarantine_id}/export-preview")
    def export_preview(
        quarantine_id: str,
        principal: Annotated[ReviewPrincipal, Depends(preview_principal)],
    ):
        del principal
        results = guarded_transition(
            lambda: review_service.export_released(
                quarantine_id,
                dry_run=True,
            )
        )
        return present_results(results)

    @app.post("/api/v1/review/records/{quarantine_id}/export")
    def export(
        quarantine_id: str,
        principal: Annotated[ReviewPrincipal, Depends(export_principal)],
    ):
        if not settings.allow_export:
            raise HTTPException(status_code=403, detail="real export is disabled")
        try:
            api_client = opencti_client_factory()
            dedup = build_export_dedup(settings, api_client)
        except ValueError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        results = guarded_transition(
            lambda: review_service.export_released(
                quarantine_id,
                api_client=api_client,
                artifact_dedup=dedup,
                identity_name=settings.identity_name,
                dry_run=False,
                exported_by=f"review-api:{principal.principal}",
            )
        )
        response = present_results(results)
        if any(item["action"] == "error" for item in response["items"]):
            raise HTTPException(status_code=502, detail=response)
        return response

    return app


def main():
    settings = load_review_api_settings()
    app = create_app(settings=settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        access_log=True,
        server_header=False,
        date_header=False,
    )


if __name__ == "__main__":
    main()
