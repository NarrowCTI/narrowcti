"""Configuration owned by the Community Web role and its explorer providers."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit


def _strict_bool(value: str | None, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise ValueError(f"{name} must be true/false, 1/0, or yes/no")


@dataclass(frozen=True)
class SourceExplorerSettings:
    misp_url: str = ""
    misp_key_file: str = field(default="", repr=False)
    misp_verify_tls: bool = True
    otx_key_file: str = field(default="", repr=False)
    max_response_bytes: int = 1_000_000

    def __post_init__(self):
        if self.max_response_bytes < 1024 or self.max_response_bytes > 1_000_000:
            raise ValueError("Source Explorer response limit must be between 1 KiB and 1 MiB")


@dataclass(frozen=True)
class WebSettings:
    host: str = "127.0.0.1"
    port: int = 8081
    credentials_file: str = ""
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    public_origin: str = ""
    cookie_secure: bool = True
    max_request_body_bytes: int = 16384
    session_idle_seconds: int = 1800
    session_absolute_seconds: int = 28800
    decision_audit_dir: str = "/app/state/audit"
    sources: SourceExplorerSettings = field(default_factory=SourceExplorerSettings)

    def __post_init__(self):
        if not 1 <= self.port <= 65535:
            raise ValueError("web port must be between 1 and 65535")
        if not self.allowed_hosts:
            raise ValueError("web allowed hosts must not be empty")
        if self.public_origin:
            origin = urlsplit(self.public_origin)
            if (
                origin.scheme not in {"http", "https"}
                or not origin.hostname
                or origin.username is not None
                or origin.password is not None
                or origin.path not in {"", "/"}
                or origin.query
                or origin.fragment
            ):
                raise ValueError("Web public origin must be an absolute HTTP(S) origin without a path")
            if origin.scheme == "http" and origin.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("a non-local Web public origin must use HTTPS")
        if not self.cookie_secure and self.host not in {"127.0.0.1", "localhost"}:
            raise ValueError("insecure Web cookies are permitted only for local HTTP development")
        if not 1024 <= self.max_request_body_bytes <= 1_000_000:
            raise ValueError("web request body limit must be between 1 KiB and 1 MiB")
        if self.session_idle_seconds < 60 or self.session_absolute_seconds < self.session_idle_seconds:
            raise ValueError("web session expiry settings are invalid")


def load_web_settings(environ: Mapping[str, str] | None = None) -> WebSettings:
    env = os.environ if environ is None else environ
    legacy_hosts = env.get("NARROWCTI_REVIEW_API_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")
    hosts = tuple(
        item.strip()
        for item in env.get("NARROWCTI_WEB_ALLOWED_HOSTS", legacy_hosts).split(",")
        if item.strip()
    )
    source_settings = SourceExplorerSettings(
        misp_url=env.get("NARROWCTI_WEB_MISP_URL", "").strip(),
        misp_key_file=env.get("NARROWCTI_WEB_MISP_KEY_FILE", "").strip(),
        misp_verify_tls=_strict_bool(
            env.get("NARROWCTI_WEB_MISP_VERIFY_TLS"),
            name="NARROWCTI_WEB_MISP_VERIFY_TLS",
            default=True,
        ),
        otx_key_file=env.get("NARROWCTI_WEB_OTX_KEY_FILE", "").strip(),
        max_response_bytes=int(env.get("NARROWCTI_WEB_SOURCE_MAX_RESPONSE_BYTES", "1000000")),
    )
    return WebSettings(
        host=env.get("NARROWCTI_REVIEW_API_HOST", "127.0.0.1"),
        port=int(env.get("NARROWCTI_REVIEW_API_PORT", "8081")),
        credentials_file=env.get("NARROWCTI_REVIEW_API_CREDENTIALS_FILE", ""),
        allowed_hosts=hosts,
        public_origin=env.get("NARROWCTI_WEB_PUBLIC_ORIGIN", "").strip().rstrip("/"),
        cookie_secure=_strict_bool(
            env.get("NARROWCTI_WEB_COOKIE_SECURE"),
            name="NARROWCTI_WEB_COOKIE_SECURE",
            default=True,
        ),
        max_request_body_bytes=int(
            env.get("NARROWCTI_WEB_MAX_BODY_BYTES", env.get("NARROWCTI_REVIEW_API_MAX_BODY_BYTES", "16384"))
        ),
        session_idle_seconds=int(env.get("NARROWCTI_WEB_SESSION_IDLE_SECONDS", "1800")),
        session_absolute_seconds=int(env.get("NARROWCTI_WEB_SESSION_ABSOLUTE_SECONDS", "28800")),
        decision_audit_dir=env.get("NARROWCTI_DECISION_AUDIT_DIR", "/app/state/audit"),
        sources=source_settings,
    )


__all__ = ["SourceExplorerSettings", "WebSettings", "load_web_settings"]
