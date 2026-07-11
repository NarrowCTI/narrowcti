import random
import time
from urllib.parse import quote

import requests

from core.retry import retry_delay


class MISPClient:
    def __init__(
        self,
        base_url,
        api_key,
        search_timeout=45,
        enrich_timeout=60,
        retries=3,
        retry_backoff_seconds=3,
        retry_jitter_seconds=1,
        verify_tls=True,
        logger=None,
        sleeper=time.sleep,
        random_fn=random.uniform,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.search_timeout = search_timeout
        self.enrich_timeout = enrich_timeout
        self.retries = retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self.retry_jitter_seconds = retry_jitter_seconds
        self.verify_tls = verify_tls
        self.logger = logger or (lambda msg: None)
        self.sleeper = sleeper
        self.random_fn = random_fn

    def headers(self):
        return {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Connection": "close",
            "User-Agent": "NarrowCTI Gateway",
        }

    def request_json(self, method, path, payload=None, timeout_seconds=30):
        url = f"{self.base_url}/{path.lstrip('/')}"

        for attempt in range(self.retries):
            try:
                self.logger(f"MISP HTTP request attempt {attempt + 1}: {method} {url}")
                response = requests.request(
                    method,
                    url,
                    headers=self.headers(),
                    json=payload,
                    timeout=(5, timeout_seconds),
                    verify=self.verify_tls,
                )
                self.logger(f"MISP HTTP status: {response.status_code}")

                if response.status_code in (200, 201):
                    return response.json()

                if response.status_code in (401, 403):
                    self.logger("MISP auth error or invalid API key")
                    return None

                if response.status_code == 429:
                    self.logger("MISP rate limit reached")

                if 500 <= response.status_code < 600:
                    self.logger("MISP upstream error")

            except requests.exceptions.ReadTimeout:
                self.logger("MISP read timeout")
            except requests.exceptions.ConnectTimeout:
                self.logger("MISP connect timeout")
            except requests.exceptions.RequestException as exc:
                self.logger(f"MISP HTTP error: {exc}")

            self.sleeper(
                retry_delay(
                    attempt + 1,
                    self.retry_backoff_seconds,
                    self.retry_jitter_seconds,
                    self.random_fn,
                )
            )

        self.logger("MISP request failed completely")
        return None

    @staticmethod
    def event_records(data):
        if not data:
            return []

        if isinstance(data, list):
            return [event for item in data for event in MISPClient.event_records(item)]

        if not isinstance(data, dict):
            return []

        if isinstance(data.get("Event"), dict):
            return [data["Event"]]

        response = data.get("response")
        if isinstance(response, list):
            return [event for item in response for event in MISPClient.event_records(item)]

        if isinstance(response, dict):
            return MISPClient.event_records(response)

        return []

    def search_events(self, query=None, limit=None, metadata=False, filters=None):
        payload = {
            "returnFormat": "json",
            "metadata": metadata,
            "includeEventTags": True,
            "includeAttributeTags": True,
        }
        if query and str(query).strip() not in ("*", "__all__"):
            payload["searchall"] = query
        if limit:
            payload["limit"] = limit
        for key, value in (filters or {}).items():
            if value not in (None, "", []):
                payload[key] = value

        data = self.request_json(
            "POST",
            "/events/restSearch",
            payload=payload,
            timeout_seconds=self.search_timeout,
        )
        return self.event_records(data)

    def get_event(self, event_id):
        safe_event_id = quote(str(event_id), safe="")
        data = self.request_json(
            "GET",
            f"/events/view/{safe_event_id}",
            timeout_seconds=self.enrich_timeout,
        )
        events = self.event_records(data)
        return events[0] if events else None
