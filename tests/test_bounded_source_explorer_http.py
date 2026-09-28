"""Security contracts for Source Explorer's bounded provider transport."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from narrowcti.adapters.sources.bounded_http import request_json, validate_base_url
from narrowcti.ports.source_explorer import ExplorerError


class _Response:
    def __init__(self, status=200, chunks=(b'{"ok":true}',), headers=None):
        self.status_code = status
        self.headers = headers or {}
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_content(self, chunk_size):
        return iter(self._chunks)


class BoundedHTTPTests(unittest.TestCase):
    def test_endpoint_validation_rejects_credentials_query_and_unsupported_scheme(self):
        self.assertEqual(validate_base_url("https://misp.example/api/"), "https://misp.example/api")
        for invalid in (
            "",
            "ftp://misp.example",
            "https://user:secret@misp.example",
            "https://misp.example?token=secret",
            "https://misp.example/#fragment",
        ):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                validate_base_url(invalid)

    @patch("narrowcti.adapters.sources.bounded_http.requests.Session")
    def test_request_disables_environment_proxy_and_redirects_and_keeps_tls_verification(self, session_factory):
        session = session_factory.return_value
        session.request.return_value = _Response()

        result = request_json(
            "GET",
            "https://misp.example/api/item",
            headers={"Authorization": "synthetic-secret"},
            verify_tls=True,
        )

        self.assertEqual(result, {"ok": True})
        self.assertFalse(session.trust_env)
        self.assertEqual(session.request.call_args.kwargs["allow_redirects"], False)
        self.assertTrue(session.request.call_args.kwargs["verify"])
        self.assertTrue(session.request.call_args.kwargs["stream"])
        session.close.assert_called_once_with()

    @patch("narrowcti.adapters.sources.bounded_http.requests.Session")
    def test_redirect_and_declared_oversized_response_are_rejected(self, session_factory):
        session = session_factory.return_value
        session.request.return_value = _Response(status=302)
        with self.assertRaises(ExplorerError) as caught:
            request_json("GET", "https://misp.example", headers={})
        self.assertEqual(caught.exception.code, "upstream_redirect")

        session.request.return_value = _Response(headers={"Content-Length": "20"})
        with self.assertRaises(ExplorerError) as caught:
            request_json("GET", "https://misp.example", headers={}, max_response_bytes=10)
        self.assertEqual(caught.exception.code, "response_too_large")

    @patch("narrowcti.adapters.sources.bounded_http.requests.Session")
    def test_chunked_response_is_stopped_at_byte_limit(self, session_factory):
        session = session_factory.return_value
        session.request.return_value = _Response(chunks=(b"123456", b"78901"))

        with self.assertRaises(ExplorerError) as caught:
            request_json("GET", "https://misp.example", headers={}, max_response_bytes=10)

        self.assertEqual(caught.exception.code, "response_too_large")


if __name__ == "__main__":
    unittest.main()
