"""Streaming request limits and outer security-header contracts."""

from __future__ import annotations

import asyncio
import unittest

from narrowcti.api.web.middleware import RequestBodyLimitMiddleware, SecurityHeadersMiddleware


def _scope(headers=()):
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/unsafe",
        "raw_path": b"/unsafe",
        "query_string": b"",
        "root_path": "",
        "headers": list(headers),
        "client": ("127.0.0.1", 1234),
        "server": ("example.test", 443),
    }


class WebMiddlewareTests(unittest.TestCase):
    def test_chunked_request_is_counted_and_413_keeps_outer_security_headers(self):
        called = []

        async def endpoint(_scope, _receive, _send):
            called.append(True)

        app = SecurityHeadersMiddleware(
            RequestBodyLimitMiddleware(endpoint, maximum_bytes=4),
            secure_cookies=True,
        )
        messages = iter(
            (
                {"type": "http.request", "body": b"123", "more_body": True},
                {"type": "http.request", "body": b"45", "more_body": False},
            )
        )
        sent = []

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        asyncio.run(app(_scope([(b"transfer-encoding", b"chunked")]), receive, send))

        response = sent[0]
        headers = dict(response["headers"])
        self.assertEqual(response["status"], 413)
        self.assertIn(b"default-src 'none'", headers[b"content-security-policy"])
        self.assertIn(b"max-age=31536000", headers[b"strict-transport-security"])
        self.assertEqual(called, [])

    def test_bounded_chunked_body_reaches_router_as_single_replayed_message(self):
        received = []

        async def endpoint(_scope, receive, send):
            received.append(await receive())
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        app = RequestBodyLimitMiddleware(endpoint, maximum_bytes=4)
        messages = iter(
            (
                {"type": "http.request", "body": b"12", "more_body": True},
                {"type": "http.request", "body": b"34", "more_body": False},
            )
        )
        sent = []

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        asyncio.run(app(_scope([(b"transfer-encoding", b"chunked")]), receive, send))

        self.assertEqual(received, [{"type": "http.request", "body": b"1234", "more_body": False}])
        self.assertEqual(sent[0]["status"], 204)


if __name__ == "__main__":
    unittest.main()
