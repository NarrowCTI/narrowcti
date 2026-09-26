"""Pure deployment endpoint validation.

This module deliberately does not perform DNS, socket, Docker or HTTP I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class EndpointDiagnostic:
    name: str
    configured: bool
    scheme: str = ""
    hostname: str = ""
    port: int | None = None
    tls_expected: bool | None = None
    code: str = ""
    message: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "configured": self.configured,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "tls_expected": self.tls_expected,
            "code": self.code,
            "message": self.message,
        }


def validate_endpoint(name: str, value: str | None, *, required: bool = True) -> EndpointDiagnostic:
    raw = str(value or "").strip()
    if not raw:
        return EndpointDiagnostic(
            name=name,
            configured=False,
            code="endpoint-missing" if required else "endpoint-not-configured",
            message=f"{name} is not configured" if required else f"{name} is not active",
        )

    parsed = urlsplit(raw)
    if parsed.username or parsed.password:
        return EndpointDiagnostic(
            name=name,
            configured=True,
            scheme=parsed.scheme.lower(),
            code="endpoint-credentials-embedded",
            message=f"{name} must not contain URL credentials",
        )
    if parsed.scheme.lower() not in {"http", "https"}:
        return EndpointDiagnostic(
            name=name,
            configured=True,
            scheme=parsed.scheme.lower(),
            code="endpoint-invalid",
            message=f"{name} must use http or https",
        )
    if not parsed.hostname:
        return EndpointDiagnostic(
            name=name,
            configured=True,
            scheme=parsed.scheme.lower(),
            code="endpoint-invalid",
            message=f"{name} must contain a hostname",
        )
    try:
        port = parsed.port
    except ValueError:
        return EndpointDiagnostic(
            name=name,
            configured=True,
            scheme=parsed.scheme.lower(),
            hostname=parsed.hostname,
            code="endpoint-invalid",
            message=f"{name} contains an invalid port",
        )
    return EndpointDiagnostic(
        name=name,
        configured=True,
        scheme=parsed.scheme.lower(),
        hostname=parsed.hostname,
        port=port,
        tls_expected=parsed.scheme.lower() == "https",
        code="ok",
        message=f"{name} endpoint structure is valid",
    )


def validate_configured_endpoints(
    *,
    opencti_url: str | None,
    misp_url: str | None,
    enabled_sources: tuple[str, ...] = ("otx", "misp"),
) -> tuple[EndpointDiagnostic, ...]:
    enabled = {str(source).strip().lower() for source in enabled_sources}
    return (
        validate_endpoint("OPENCTI_URL", opencti_url, required=bool(enabled & {"otx", "misp"})),
        validate_endpoint("MISP_URL", misp_url, required="misp" in enabled),
    )


def validate_state_path(path: str | None) -> EndpointDiagnostic:
    """Check state readiness without changing ownership, mode or filesystem."""

    raw = str(path or "").strip()
    if not raw:
        return EndpointDiagnostic(
            name="NARROWCTI_STATE_DIR",
            configured=False,
            code="state-path-not-configured",
            message="NARROWCTI_STATE_DIR is empty",
        )
    state_path = Path(raw)
    if state_path.exists() and not state_path.is_dir():
        return EndpointDiagnostic(
            name="NARROWCTI_STATE_DIR",
            configured=True,
            code="state-path-not-directory",
            message=f"state path is not a directory: {state_path}",
        )
    if state_path.exists() and not os.access(state_path, os.W_OK | os.X_OK):
        return EndpointDiagnostic(
            name="NARROWCTI_STATE_DIR",
            configured=True,
            code="state-path-not-writable",
            message=f"state path is not writable: {state_path}",
        )
    if state_path.exists():
        return EndpointDiagnostic(
            name="NARROWCTI_STATE_DIR",
            configured=True,
            code="ok",
            message="state path is an existing writable directory",
        )

    parent = state_path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        return EndpointDiagnostic(
            name="NARROWCTI_STATE_DIR",
            configured=True,
            code="state-path-parent-not-writable",
            message=f"state path does not exist and nearest parent is not writable: {parent}",
        )
    return EndpointDiagnostic(
        name="NARROWCTI_STATE_DIR",
        configured=True,
        code="state-path-absent",
        message=f"state path does not exist; nearest existing parent is writable: {parent}",
    )


__all__ = [
    "EndpointDiagnostic",
    "validate_endpoint",
    "validate_configured_endpoints",
    "validate_state_path",
]
