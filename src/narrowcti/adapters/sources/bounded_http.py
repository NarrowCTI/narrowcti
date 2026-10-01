"""Small bounded HTTP transport for configured Source Explorer endpoints."""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import requests

from narrowcti.ports.source_explorer import ExplorerError


DEFAULT_MAX_RESPONSE_BYTES = 2_000_000
DEFAULT_TOTAL_TIMEOUT_SECONDS = 15.0
_CHUNK_SIZE = 64 * 1024


def validate_base_url(value: str) -> str:
    """Accept an explicitly configured HTTP(S) origin without embedded secrets."""
    url = str(value or "").strip()
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("source explorer endpoint must be an absolute HTTP(S) URL without credentials")
    return url.rstrip("/")


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    verify_tls: bool = True,
    connect_timeout: float = 5.0,
    read_timeout: float = 10.0,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> object:
    """Make one non-redirecting, environment-independent, byte-bounded request."""
    if max_response_bytes < 1 or total_timeout <= 0:
        raise ValueError("HTTP response limits must be positive")
    session = requests.Session()
    session.trust_env = False
    started = time.monotonic()
    try:
        with session.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=(connect_timeout, read_timeout),
            verify=verify_tls,
            allow_redirects=False,
            stream=True,
        ) as response:
            if 300 <= response.status_code < 400:
                raise ExplorerError("upstream_redirect", "The source provider redirected the request.")
            if response.status_code == 404:
                raise ExplorerError("source_not_found", "The requested source item was not found.")
            if response.status_code in {401, 403}:
                raise ExplorerError("provider_auth_failed", "The source provider rejected its configured credential.")
            if response.status_code == 429:
                raise ExplorerError("provider_rate_limited", "The source provider is rate limiting requests.", True)
            if response.status_code < 200 or response.status_code >= 300:
                retryable = response.status_code >= 500
                raise ExplorerError("provider_unavailable", "The source provider could not complete the request.", retryable)

            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > max_response_bytes:
                        raise ExplorerError("response_too_large", "The source response exceeded the configured size limit.")
                except ValueError:
                    raise ExplorerError("invalid_provider_response", "The source provider returned an invalid response.") from None

            chunks: list[bytes] = []
            received = 0
            for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
                if time.monotonic() - started > total_timeout:
                    raise ExplorerError("provider_timeout", "The source provider request timed out.", True)
                if not chunk:
                    continue
                received += len(chunk)
                if received > max_response_bytes:
                    raise ExplorerError("response_too_large", "The source response exceeded the configured size limit.")
                chunks.append(chunk)
            if time.monotonic() - started > total_timeout:
                raise ExplorerError("provider_timeout", "The source provider request timed out.", True)
        try:
            return json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ExplorerError("invalid_provider_response", "The source provider returned invalid JSON.") from None
    except ExplorerError:
        raise
    except requests.RequestException:
        raise ExplorerError("provider_unavailable", "The source provider could not be reached.", True) from None
    finally:
        session.close()


def probe_status(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    verify_tls: bool = True,
    connect_timeout: float = 3.0,
    read_timeout: float = 5.0,
    total_timeout: float = 8.0,
) -> int:
    """Return only the HTTP status from one bounded non-redirecting probe.

    The response body is never read, parsed, logged or retained.
    """
    if min(connect_timeout, read_timeout, total_timeout) <= 0:
        raise ValueError("HTTP probe timeouts must be positive")
    session = requests.Session()
    session.trust_env = False
    started = time.monotonic()
    try:
        with session.request(
            method,
            url,
            headers=headers,
            params=params,
            timeout=(connect_timeout, read_timeout),
            verify=verify_tls,
            allow_redirects=False,
            stream=True,
        ) as response:
            if time.monotonic() - started > total_timeout:
                raise ExplorerError("provider_timeout", "The source provider readiness check timed out.", True)
            return int(response.status_code)
    except ExplorerError:
        raise
    except requests.exceptions.SSLError:
        raise ExplorerError("provider_tls_failed", "The source provider TLS check failed.") from None
    except requests.exceptions.Timeout:
        raise ExplorerError("provider_timeout", "The source provider readiness check timed out.", True) from None
    except requests.RequestException:
        raise ExplorerError("provider_unavailable", "The source provider could not be reached.", True) from None
    finally:
        session.close()


__all__ = ["DEFAULT_MAX_RESPONSE_BYTES", "DEFAULT_TOTAL_TIMEOUT_SECONDS", "probe_status", "request_json", "validate_base_url"]
