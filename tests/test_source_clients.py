import unittest
from types import SimpleNamespace
from unittest.mock import patch

from connectors.misp.client import MISPClient, MISPRequestError
from connectors.otx.otx_client import OTXClient, OTXRequestError


class MISPRequestFailureTests(unittest.TestCase):
    @patch("connectors.misp.client.requests.request")
    def test_upstream_failure_raises_after_retries(self, request):
        request.return_value = SimpleNamespace(status_code=503)
        sleeps = []
        client = MISPClient(
            "http://misp.local",
            "key",
            retries=2,
            retry_backoff_seconds=1,
            retry_jitter_seconds=0,
            sleeper=sleeps.append,
        )

        with self.assertRaisesRegex(MISPRequestError, "HTTP 503"):
            client.get_event("5564")

        self.assertEqual(2, request.call_count)
        self.assertEqual([1], sleeps)

    @patch("connectors.misp.client.requests.request")
    def test_auth_failure_raises_without_retrying(self, request):
        request.return_value = SimpleNamespace(status_code=403)
        client = MISPClient("http://misp.local", "key", retries=3, sleeper=lambda _: None)

        with self.assertRaisesRegex(MISPRequestError, "authentication failed"):
            client.get_event("5564")

        self.assertEqual(1, request.call_count)


class OTXRequestFailureTests(unittest.TestCase):
    @patch("connectors.otx.otx_client.requests.get")
    def test_upstream_failure_raises_after_retries(self, request):
        request.return_value = SimpleNamespace(status_code=503)
        sleeps = []
        client = OTXClient(
            "key",
            retries=2,
            retry_backoff_seconds=1,
            retry_jitter_seconds=0,
            sleeper=sleeps.append,
        )

        with self.assertRaisesRegex(OTXRequestError, "HTTP 503"):
            client.search_pulses("lummac2")

        self.assertEqual(2, request.call_count)
        self.assertEqual([1], sleeps)

    @patch("connectors.otx.otx_client.requests.get")
    def test_auth_failure_raises_without_retrying(self, request):
        request.return_value = SimpleNamespace(status_code=403)
        client = OTXClient("key", retries=3, sleeper=lambda _: None)

        with self.assertRaisesRegex(OTXRequestError, "authentication failed"):
            client.search_pulses("lummac2")

        self.assertEqual(1, request.call_count)


if __name__ == "__main__":
    unittest.main()
