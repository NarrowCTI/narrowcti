"""Typed, dependency-free configuration primitives.

Source-specific settings modules remain the compatibility boundary for legacy
environment variable names. This module owns deterministic mapping resolution,
strict security parsing, active-surface validation and safe representations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping


Environment = Mapping[str, str]
_TRUE_VALUES = frozenset({"true", "1", "yes"})
_STRICT_FALSE_VALUES = frozenset({"false", "0", "no"})


def environment(environ: Environment | None = None) -> Environment:
    """Return an explicit environment mapping or the process environment."""

    return os.environ if environ is None else environ


def env_value(environ: Environment, name: str, default: str | None = None) -> str | None:
    value = environ.get(name)
    return default if value is None else str(value)


def env_required(environ: Environment, name: str) -> str:
    value = environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required variable: {name}")
    return str(value)


def parse_bool(value: str | None, default: bool = False) -> bool:
    """Preserve historical permissive boolean semantics for non-security flags."""

    if value is None:
        return default
    # Legacy loaders compared the raw value after lower-casing only.  Keep
    # that permissive contract unchanged; security-sensitive parsing uses the
    # strict parser below and is the only place that normalizes whitespace.
    return str(value).lower() in _TRUE_VALUES


def parse_misp_verify_tls(value: str | None) -> bool:
    """Parse MISP TLS strictly and fail closed."""

    if value is None:
        return True
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _STRICT_FALSE_VALUES:
        return False
    raise ValueError("MISP_VERIFY_TLS must be one of true/1/yes or false/0/no")


def env_int(environ: Environment, name: str, default: int) -> int:
    return int(env_value(environ, name, str(default)))


def env_bool(environ: Environment, name: str, default: bool = False) -> bool:
    return parse_bool(env_value(environ, name), default)


def env_int_alias(
    environ: Environment,
    primary: str,
    fallback: str,
    default: int,
) -> int:
    value = env_value(environ, primary)
    if value is None:
        value = env_value(environ, fallback)
    return default if value is None else int(value)


def env_bool_alias(
    environ: Environment,
    primary: str,
    fallback: str,
    default: bool = False,
) -> bool:
    value = env_value(environ, primary)
    if value is None:
        value = env_value(environ, fallback)
    return parse_bool(value, default)


def env_list(environ: Environment, name: str, default: str = "") -> list[str]:
    raw = env_value(environ, name, default) or ""
    return [value.strip() for value in raw.split(",") if value.strip()]


def require_nonnegative(name, value):
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def require_positive(name, value):
    if value < 1:
        raise ValueError(f"{name} must be greater than zero")
    return value


@dataclass(frozen=True)
class OpenCTIConfig:
    """OpenCTI connection values with structural secret redaction."""

    url: str
    token: str = field(repr=False)

    def to_safe_dict(self) -> dict[str, object]:
        return {"url": self.url, "configured": bool(self.token)}


@dataclass(frozen=True)
class SourceConnectionConfig:
    """A source connection used by an active connector only."""

    name: str
    url: str
    credential: str = field(repr=False)

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "url": self.url,
            "configured": bool(self.credential),
        }


@dataclass(frozen=True)
class RuntimeConfig:
    """Composable active-surface configuration snapshot."""

    opencti: OpenCTIConfig | None = None
    misp: SourceConnectionConfig | None = None
    otx: SourceConnectionConfig | None = None
    misp_verify_tls: bool = True

    def to_safe_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"misp_verify_tls": self.misp_verify_tls}
        if self.opencti is not None:
            result["opencti"] = self.opencti.to_safe_dict()
        if self.misp is not None:
            result["misp"] = self.misp.to_safe_dict()
        if self.otx is not None:
            result["otx"] = self.otx.to_safe_dict()
        return result


def load_opencti_config(
    environ: Environment,
    *,
    required: bool = True,
) -> OpenCTIConfig | None:
    url = str(environ.get("OPENCTI_URL") or "").strip()
    token = str(environ.get("OPENCTI_TOKEN") or "").strip()
    if not url and not token and not required:
        return None
    if required and (not url or not token):
        raise RuntimeError("OPENCTI_URL and OPENCTI_TOKEN are required")
    return OpenCTIConfig(url=url, token=token)


def load_runtime_config(
    environ: Environment | None = None,
    *,
    enabled_sources: tuple[str, ...] | list[str] = (),
    require_review_api: bool = False,
    require_opencti: bool = False,
) -> RuntimeConfig:
    """Resolve credentials only for active consumers."""

    env = environment(environ)
    sources = {str(source).strip().lower() for source in enabled_sources}
    needs_opencti = require_opencti or require_review_api or bool(
        sources & {"misp", "otx"}
    )
    opencti = load_opencti_config(env, required=needs_opencti)
    misp = None
    if "misp" in sources:
        misp = SourceConnectionConfig(
            name="misp",
            url=env_required(env, "MISP_URL"),
            credential=env_required(env, "MISP_KEY"),
        )
    otx = None
    if "otx" in sources:
        otx = SourceConnectionConfig(
            name="otx",
            url="https://otx.alienvault.com",
            credential=env_required(env, "OTX_API_KEY"),
        )
    misp_verify_tls = (
        parse_misp_verify_tls(env_value(env, "MISP_VERIFY_TLS"))
        if "misp" in sources
        else True
    )
    return RuntimeConfig(
        opencti=opencti,
        misp=misp,
        otx=otx,
        misp_verify_tls=misp_verify_tls,
    )
