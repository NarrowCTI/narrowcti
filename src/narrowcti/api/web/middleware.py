"""Outer security headers and streaming request-body bounds for the Web role."""

from __future__ import annotations

from starlette.datastructures import Headers, MutableHeaders


class RequestBodyLimitMiddleware:
    def __init__(self, app, maximum_bytes: int):
        if maximum_bytes < 1:
            raise ValueError("maximum request body must be positive")
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                await self._respond(send, 400, b"invalid content length")
                return
            if declared < 0:
                await self._respond(send, 400, b"invalid content length")
                return
            if declared > self.maximum_bytes:
                await self._respond(send, 413, b"request body too large")
                return

        chunks: list[bytes] = []
        body_size = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            body_size += len(chunk)
            if body_size > self.maximum_bytes:
                await self._respond(send, 413, b"request body too large")
                return
            if chunk:
                chunks.append(chunk)
            more_body = bool(message.get("more_body", False))

        body = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _respond(send, status: int, body: bytes):
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})


class SecurityHeadersMiddleware:
    def __init__(self, app, *, secure_cookies: bool):
        self.app = app
        self.secure_cookies = secure_cookies

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("Cache-Control", "no-store")
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
                headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                headers["Content-Security-Policy"] = (
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                    "connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; "
                    "frame-ancestors 'none'"
                )
                if self.secure_cookies:
                    headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            await send(message)

        await self.app(scope, receive, send_with_headers)


__all__ = ["RequestBodyLimitMiddleware", "SecurityHeadersMiddleware"]
