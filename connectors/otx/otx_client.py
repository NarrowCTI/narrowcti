import time

import requests


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
        logger=None,
    ):
        self.api_key = api_key
        self.search_timeout = search_timeout
        self.enrich_timeout = enrich_timeout
        self.retries = retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self.logger = logger or (lambda msg: None)

    def headers(self):
        return {
            "X-OTX-API-KEY": self.api_key,
            "Connection": "close",
            "User-Agent": "curl/7.88.1",
        }

    def request_json(self, url, params=None, timeout_seconds=30):
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
                    return None

                if response.status_code == 429:
                    self.logger("OTX rate limit reached")

                if 500 <= response.status_code < 600:
                    self.logger("OTX upstream error")

            except requests.exceptions.ReadTimeout:
                self.logger("Read timeout")
            except requests.exceptions.ConnectTimeout:
                self.logger("Connect timeout")
            except requests.exceptions.RequestException as exc:
                self.logger(f"HTTP error: {exc}")

            time.sleep((attempt + 1) * self.retry_backoff_seconds)

        self.logger("Request failed completely")
        return None

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
