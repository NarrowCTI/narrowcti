import random
import time

import requests

from core.retry import retry_delay


class OTXRequestError(RuntimeError):
    pass


class OTXClient:
    SEARCH_URL = "https://otx.alienvault.com/api/v1/search/pulses"
    PULSE_URL = "https://otx.alienvault.com/api/v1/pulses/{pulse_id}"

    def __init__(
        self,
        api_key,
        search_timeout=45,
        enrich_timeout=60,
        retries=3,
        retry_backoff_seconds=3,
        retry_jitter_seconds=1,
        logger=None,
        sleeper=time.sleep,
        random_fn=random.uniform,
    ):
        self.api_key = api_key
        self.search_timeout = search_timeout
        self.enrich_timeout = enrich_timeout
        self.retries = retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self.retry_jitter_seconds = retry_jitter_seconds
        self.logger = logger or (lambda msg: None)
        self.sleeper = sleeper
        self.random_fn = random_fn

    def headers(self):
        return {
            "X-OTX-API-KEY": self.api_key,
            "Connection": "close",
            "User-Agent": "curl/7.88.1",
        }

    def request_json(self, url, params=None, timeout_seconds=30):
        last_error = "unknown error"
        for attempt in range(self.retries):
            try:
                self.logger(f"HTTP request attempt {attempt + 1}: {url}")
                response = requests.get(
                    url,
                    headers=self.headers(),
                    params=params,
                    timeout=(5, timeout_seconds),
                    verify=True,
                )
                self.logger(f"HTTP status: {response.status_code}")

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 403:
                    self.logger("Auth error or invalid OTX API key")
                    raise OTXRequestError("OTX authentication failed with HTTP 403")

                if response.status_code == 404:
                    self.logger("OTX object not found")
                    return None

                if response.status_code == 429:
                    self.logger("OTX rate limit reached")

                if 500 <= response.status_code < 600:
                    self.logger("OTX upstream error")

                last_error = f"HTTP {response.status_code}"

            except requests.exceptions.ReadTimeout:
                self.logger("Read timeout")
                last_error = "read timeout"
            except requests.exceptions.ConnectTimeout:
                self.logger("Connect timeout")
                last_error = "connect timeout"
            except requests.exceptions.RequestException as exc:
                self.logger(f"HTTP error: {exc}")
                last_error = str(exc)

            if attempt + 1 < self.retries:
                self.sleeper(
                    retry_delay(
                        attempt + 1,
                        self.retry_backoff_seconds,
                        self.retry_jitter_seconds,
                        self.random_fn,
                    )
                )

        self.logger("Request failed completely")
        raise OTXRequestError(
            f"OTX request failed after {self.retries} attempts: {last_error}"
        )

    def search_pulses(self, query):
        self.logger(f"Searching OTX: {query}")
        data = self.request_json(
            self.SEARCH_URL,
            params={"q": query},
            timeout_seconds=self.search_timeout,
        )
        if not data:
            return []
        return data.get("results", [])

    def enrich_pulse(self, pulse_id):
        return self.request_json(
            self.PULSE_URL.format(pulse_id=pulse_id),
            timeout_seconds=self.enrich_timeout,
        )
