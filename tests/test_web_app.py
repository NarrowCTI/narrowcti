"""HTTP contracts for browser sessions, CSRF, Source Explorer and API coexistence."""

from __future__ import annotations

import re
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from narrowcti.api.review.app import ReviewApiSettings, create_app as create_review_api_app
from narrowcti.api.review.auth import ReviewCredentialStore, token_sha256
from narrowcti.api.web.app import SESSION_COOKIE_LOCAL, SESSION_COOKIE_SECURE, create_web_app
from narrowcti.infrastructure.config.web_settings import WebSettings, load_web_settings
from narrowcti.api.web.sessions import InMemoryWebSessionStore
from narrowcti.adapters.persistence.local.operator_store import LocalOperatorStore
from narrowcti.application.identity.passwords import LocalOperatorAuthenticator, PasswordService
from narrowcti.application.reporting.web_evidence import WebEvidenceService
from narrowcti.adapters.persistence.local.operational_snapshot_store import LocalOperationalSnapshotStore
from narrowcti.infrastructure.runtime.operational_snapshot import (
    publish_gateway_preflight_snapshot,
    publish_operational_validation_snapshot,
)
from gateway.preflight import build_preflight_report
from gateway.decisions import build_decision_audit_report
from gateway.operational_validation import build_operational_validation_report
from gateway.settings import load_settings as load_gateway_settings
from narrowcti.adapters.persistence.local.decision_audit_reader import read_decision_records
from narrowcti.ports.source_explorer import (
    ExplorerError,
    ExplorerItemDetail,
    ExplorerItemSummary,
    ExplorerSearchResult,
    ProviderDescriptor,
    ProviderOperation,
)
from argon2 import PasswordHasher
from argon2.low_level import Type


TOKEN = "synthetic-browser-login-token-not-a-real-secret"
ADMIN_TOKEN = "synthetic-browser-admin-token-not-a-real-secret"
READER_PASSWORD = "reader synthetic phrase 01"
ADMIN_PASSWORD = "admin synthetic phrase 02"


def _test_passwords():
    return PasswordService(PasswordHasher(time_cost=1, memory_cost=8, parallelism=1, hash_len=16, salt_len=8, type=Type.ID))


class _Summary:
    def to_dict(self):
        return {"pending": 0, "released": 0}


class _ReviewService:
    def __init__(self):
        self.records = []

    def summary(self):
        return _Summary()

    def list_records(self, *, status, limit):
        values = self.records if status == "all" else [item for item in self.records if item.get("status") == status]
        return values[:limit]


class _Explorer:
    def __init__(self):
        self.request = None
        self.title = "Example incident"

    def providers(self):
        return (ProviderDescriptor("misp", "MISP", True, operations=(ProviderOperation.SEARCH, ProviderOperation.DETAIL)),)

    def search(self, request):
        self.request = request
        return ExplorerSearchResult(
            provider_key="misp",
            items=(ExplorerItemSummary("misp", "42", self.title, tags=("tlp:amber",)),),
        )

    def detail(self, provider_key, external_id):
        summary = ExplorerItemSummary(
            provider_key=provider_key,
            external_id=external_id,
            title="Example incident",
            revision_fingerprint="a" * 64,
        )
        return ExplorerItemDetail(summary, {"description": "Safe detail"}, {"source": provider_key})


class _Jobs:
    def __init__(self):
        self.jobs = {}
        self.submissions = []

    def submit(self, job_type, source, payload, *, idempotency_key, active_limit=None):
        self.submissions.append((job_type, source, dict(payload), idempotency_key, active_limit))
        job = self.jobs.setdefault(
            idempotency_key,
            {
                "job_id": "job-1",
                "job_type": job_type,
                "payload": dict(payload),
                "status": "pending",
                "created_at": "2026-01-01T00:00:00Z",
                "error": None,
                "result": None,
            },
        )
        return job

    def get(self, job_id):
        return next((job for job in self.jobs.values() if job["job_id"] == job_id), None)


class _SnapshotReader:
    def __init__(self, preflight=None, validation=None):
        self.preflight = preflight
        self.validation = validation

    def read_preflight(self):
        return self.preflight

    def read_validation(self):
        return self.validation


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.operator_store = LocalOperatorStore(Path(self._temporary.name) / "auth.db")
        self.passwords = _test_passwords()
        self.admin_operator = self.operator_store.create_operator(
            "admin", self.passwords.hash_password(ADMIN_PASSWORD), ["admin"]
        )
        self.reader_operator = self.operator_store.create_operator(
            "reader", self.passwords.hash_password(READER_PASSWORD), ["reader"]
        )
        self.operator_authenticator = LocalOperatorAuthenticator(self.operator_store, self.passwords)
        self.credential_store = ReviewCredentialStore(
            (
                {
                    "principal": "reader",
                    "credential_id": "reader-key",
                    "token_sha256": token_sha256(TOKEN),
                    "roles": frozenset({"reader"}),
                },
                {
                    "principal": "admin",
                    "credential_id": "admin-key",
                    "token_sha256": token_sha256(ADMIN_TOKEN),
                    "roles": frozenset({"admin"}),
                },
            )
        )
        self.explorer = _Explorer()
        self.jobs = _Jobs()
        self.session_store = InMemoryWebSessionStore(300, 3600)
        self.settings = WebSettings(
            credentials_file="synthetic-credentials-file",
            auth_db=str(Path(self._temporary.name) / "auth.db"),
            runtime_db_file=str(Path(self._temporary.name) / "runtime.db"),
            allowed_hosts=("testserver", "localhost"),
            cookie_secure=False,
        )
        self.review_service = _ReviewService()
        api = create_review_api_app(
            settings=ReviewApiSettings(
                repository_file="synthetic-quarantine",
                release_audit_file="synthetic-audit",
                credentials_file="synthetic-credentials-file",
                allowed_hosts=("testserver", "localhost"),
            ),
            review_service=self.review_service,
            credential_store=self.credential_store,
        )
        self.review_api_app = api
        self.app = create_web_app(
            self.settings,
            source_explorer=self.explorer,
            credential_store=self.credential_store,
            operator_store=self.operator_store,
            operator_authenticator=self.operator_authenticator,
            review_api_app=api,
            session_store=self.session_store,
            job_repository=self.jobs,
            evidence_service=WebEvidenceService(lambda _limit: [{
                "recorded_at": "2026-09-28T12:00:00Z",
                "action": "quarantine",
                "reason": "synthetic safe reason",
                "source_key": "misp",
                "external_id": "event-42",
                "title": "Synthetic event",
                "indicator_count": 3,
                "metadata": {"provider_payload": "evidence-secret-canary"},
                "path": "C:/private/audit.jsonl",
            }]),
            operational_state_reader=_SnapshotReader(
                preflight={
                    "schema": "narrowcti.web-preflight/v1",
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "report": {
                    "status": "ready", "ingestion_mode": "hybrid", "dedup_mode": "hybrid",
                    "graph_export_mode": "audit", "misp_tls": True,
                    "sources": [{"name": "misp", "dry_run": True}],
                    "issues": [{"severity": "warning", "code": "mitre-cache-missing", "message": "C:/private/cache.json"}],
                    "settings": {"opencti_token": "preflight-secret-canary"},
                    "evidence_paths": {"state_dir": "C:/private/narrowcti-state"},
                },
                },
                validation={
                    "schema": "narrowcti.web-operational-validation/v1",
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "required_sources": ["misp"],
                    "report": {
                    "schema_version": "operational-validation/v1.0", "release": "v1.0.0",
                    "status": "needs-evidence", "counts": {"needs-evidence": 1},
                    "checks": [{"code": "full-validation", "status": "needs-evidence",
                                "message": "C:/private/release.log",
                                "evidence": {"api_key": "validation-secret-canary", "path": "C:/private/release.log"}}],
                },
                },
            ),
        )
        self.client = TestClient(self.app, base_url="https://testserver")

    def _login(self, client=None, token=TOKEN):
        client = client or self.client
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        anonymous_cookie = client.cookies.get(SESSION_COOKIE_LOCAL)
        self.assertIsNotNone(anonymous_cookie)
        csrf = re.search(r'name="_csrf" value="([^"]+)"', response.text).group(1)
        result = client.post(
            "/login",
            data={
                "_csrf": csrf,
                "username": "admin" if token == ADMIN_TOKEN else "reader",
                "password": ADMIN_PASSWORD if token == ADMIN_TOKEN else READER_PASSWORD,
            },
            follow_redirects=False,
        )
        self.assertEqual(result.status_code, 303)
        authenticated_cookie = client.cookies.get(SESSION_COOKIE_LOCAL)
        self.assertNotEqual(anonymous_cookie, authenticated_cookie)
        return result

    def test_browser_login_rotates_session_and_never_places_bearer_in_cookie_or_session(self):
        login_page = self.client.get("/login")
        self.assertIn('name="username"', login_page.text)
        self.assertIn('name="password"', login_page.text)
        self.assertNotIn('name="credential"', login_page.text)
        self.assertNotIn("Review API", login_page.text)
        login_response = self._login()
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn("reader", response.text)
        self.assertNotIn(TOKEN, self.client.cookies.get(SESSION_COOKIE_LOCAL))
        self.assertNotIn(TOKEN, repr(self.session_store._sessions))
        cookie = login_response.headers["set-cookie"].lower()
        self.assertIn(f"{SESSION_COOKIE_LOCAL}=", cookie)
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=lax", cookie)
        self.assertNotIn("; secure", cookie)

    def test_review_bearer_is_not_a_browser_credential_and_web_cookie_is_not_api_auth(self):
        page = self.client.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
        response = self.client.post(
            "/login",
            data={"_csrf": csrf, "username": "reader", "password": TOKEN},
            follow_redirects=False,
        )
        self.assertEqual(401, response.status_code)
        self.assertIn("Invalid username or password.", response.text)
        self._login()
        self.assertEqual(401, self.client.get("/api/v1/review/summary").status_code)

    def test_unknown_wrong_and_disabled_accounts_have_the_same_public_error(self):
        errors = []
        for username, password in (
            ("missing", READER_PASSWORD),
            ("reader", "wrong synthetic passphrase"),
        ):
            client = TestClient(self.app, base_url="https://testserver")
            page = client.get("/login")
            csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
            response = client.post("/login", data={"_csrf": csrf, "username": username, "password": password})
            errors.append((response.status_code, response.text.split("<p class=\"alert\" role=\"alert\">", 1)[1].split("</p>", 1)[0]))
        self.operator_store.set_enabled(self.reader_operator.operator_id, False)
        client = TestClient(self.app, base_url="https://testserver")
        page = client.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
        response = client.post("/login", data={"_csrf": csrf, "username": "reader", "password": READER_PASSWORD})
        errors.append((response.status_code, response.text.split("<p class=\"alert\" role=\"alert\">", 1)[1].split("</p>", 1)[0]))
        self.assertEqual([(401, "Invalid username or password.")] * 3, errors)

    def test_local_operator_setup_state_is_visible_without_default_account(self):
        empty = LocalOperatorStore(Path(self._temporary.name) / "empty-auth.db")
        app = create_web_app(
            self.settings,
            source_explorer=self.explorer,
            credential_store=self.credential_store,
            operator_store=empty,
            operator_authenticator=LocalOperatorAuthenticator(empty, self.passwords),
            review_api_app=self.review_api_app,
        )
        page = TestClient(app, base_url="https://testserver").get("/login")
        self.assertIn("No local NarrowCTI operator has been configured.", page.text)
        self.assertFalse(empty.has_operators())

    def test_account_password_form_matches_minimum_policy(self):
        self._login()
        response = self.client.get("/account")
        self.assertEqual(200, response.status_code)
        self.assertEqual(2, response.text.count('minlength="15"'))
        self.assertEqual(3, response.text.count('maxlength="1024"'))

    def test_role_disable_and_password_changes_revoke_existing_sessions(self):
        self._login()
        self.operator_store.set_roles(self.reader_operator.operator_id, ["reader", "reviewer"])
        self.assertEqual(303, self.client.get("/", follow_redirects=False).status_code)

        self._login()
        account = self.client.get("/account")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', account.text).group(1)
        changed = self.client.post(
            "/account/password",
            data={
                "_csrf": csrf,
                "current_password": READER_PASSWORD,
                "new_password": "synthetic new reader passphrase",
                "confirm_password": "synthetic new reader passphrase",
            },
            follow_redirects=False,
        )
        self.assertEqual(303, changed.status_code)
        self.assertEqual("/login", changed.headers["location"])
        self.assertEqual(303, self.client.get("/", follow_redirects=False).status_code)
        self.assertIsNone(self.operator_authenticator.authenticate("reader", READER_PASSWORD))
        self.assertIsNotNone(self.operator_authenticator.authenticate("reader", "synthetic new reader passphrase"))

        self.operator_store.set_enabled(self.reader_operator.operator_id, False)
        self.assertIsNone(self.operator_authenticator.authenticate("reader", "synthetic new reader passphrase"))
        self.operator_store.set_enabled(self.reader_operator.operator_id, True)
        self.assertEqual(303, self.client.get("/", follow_redirects=False).status_code)

    def test_browser_posts_require_csrf_and_logout_is_explicit(self):
        self.client.get("/login")
        denied = self.client.post("/login", data={"username": "reader", "password": READER_PASSWORD})
        self.assertEqual(denied.status_code, 403)

        self._login()
        denied_logout = self.client.post("/logout", data={})
        self.assertEqual(denied_logout.status_code, 403)
        csrf = self.client.get("/").text
        token = re.search(r'name="_csrf" value="([^"]+)"', csrf).group(1)
        logged_out = self.client.post("/logout", data={"_csrf": token}, follow_redirects=False)
        self.assertEqual(logged_out.status_code, 303)
        self.assertEqual(self.client.get("/", follow_redirects=False).status_code, 303)

    def test_failed_login_reuses_bounded_anonymous_session_and_is_rate_limited(self):
        login = self.client.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', login.text).group(1)
        initial_count = len(self.session_store)
        for _ in range(5):
            response = self.client.post("/login", data={"_csrf": csrf, "username": "missing-user", "password": "invalid synthetic phrase"})
            self.assertEqual(401, response.status_code)
            self.assertIn("Invalid username or password.", response.text)
        blocked = self.client.post("/login", data={"_csrf": csrf, "username": "missing-user", "password": "invalid synthetic phrase"})
        self.assertEqual(429, blocked.status_code)
        self.assertEqual(initial_count, len(self.session_store))

    def test_preview_dry_run_and_run_once_have_separate_submission_limits(self):
        self._login(client=self.client, token=ADMIN_TOKEN)
        detail = self.client.get("/explorer/misp/42")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', detail.text).group(1)
        for mode, allowed in (("preview", 10), ("dry-run", 5), ("run-once", 3)):
            for index in range(allowed):
                response = self.client.post(
                    f"/explorer/misp/42/{mode}",
                    data={"_csrf": csrf, "request_id": f"rate_{mode}_{index:02d}", "expected_fingerprint": "a" * 64},
                    follow_redirects=False,
                )
                self.assertEqual(303, response.status_code)
                if mode == "run-once":
                    _job_type, _source, _payload, key, _active_limit = self.jobs.submissions[-1]
                    self.jobs.jobs[key]["status"] = "succeeded"
            blocked = self.client.post(
                f"/explorer/misp/42/{mode}",
                data={"_csrf": csrf, "request_id": f"rate_{mode}_blocked", "expected_fingerprint": "a" * 64},
                follow_redirects=False,
            )
            self.assertEqual(429, blocked.status_code)

    def test_reader_can_search_and_search_is_a_csrf_protected_transient_post(self):
        self._login()
        page = self.client.get("/explorer")
        self.assertEqual(page.status_code, 200)
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
        denied = self.client.post("/explorer/search", data={"query": "malware"})
        self.assertEqual(denied.status_code, 403)

        response = self.client.post(
            "/explorer/search",
            data={"_csrf": csrf, "provider_key": "misp", "query": "malware", "tag": "apt"},
            headers={"HX-Request": "true"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Example incident", response.text)
        self.assertEqual(self.explorer.request.filters["tag"], ("apt",))

    def test_hostile_source_content_is_autoescaped_in_htmx_fragment(self):
        self._login()
        self.explorer.title = '<script>alert("synthetic")</script>'
        page = self.client.get("/explorer")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)

        response = self.client.post(
            "/explorer/search",
            data={"_csrf": csrf, "provider_key": "misp", "query": "untrusted"},
            headers={"HX-Request": "true"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('<script>alert("synthetic")</script>', response.text)
        self.assertIn("&lt;script&gt;", response.text)

    def test_source_evaluation_submits_identity_only_jobs_and_run_once_is_admin_only(self):
        self._login()
        detail = self.client.get("/explorer/misp/42")
        self.assertEqual(detail.status_code, 200)
        csrf = re.search(r'name="_csrf" value="([^"]+)"', detail.text).group(1)
        response = self.client.post(
            "/explorer/misp/42/preview",
            data={"_csrf": csrf, "request_id": "request_12345", "expected_fingerprint": "a" * 64},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        job_type, source, payload, key, limit = self.jobs.submissions[-1]
        self.assertEqual(("ingestion.preview", "misp", 3), (job_type, source, limit))
        self.assertEqual(
            {"source_key", "external_id", "expected_fingerprint", "request_id", "requester"},
            set(payload),
        )
        self.assertEqual("42", payload["external_id"])
        self.assertNotIn("description", payload)
        self.assertNotIn(TOKEN, repr((payload, key)))

        denied = self.client.post(
            "/explorer/misp/42/run-once",
            data={"_csrf": csrf, "request_id": "request_54321", "expected_fingerprint": "a" * 64},
            follow_redirects=False,
        )
        self.assertEqual(403, denied.status_code)

    def test_admin_can_submit_run_once_with_identity_only_job_payload(self):
        client = TestClient(self.app, base_url="https://testserver")
        self._login(client, ADMIN_TOKEN)
        detail = client.get("/explorer/misp/42")
        self.assertEqual(detail.status_code, 200)
        csrf = re.search(r'name="_csrf" value="([^"]+)"', detail.text).group(1)

        response = client.post(
            "/explorer/misp/42/run-once",
            data={"_csrf": csrf, "request_id": "admin_request_1", "expected_fingerprint": "a" * 64},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 303)
        job_type, source, payload, _key, limit = self.jobs.submissions[-1]
        self.assertEqual(("ingestion.run_once", "misp", 1), (job_type, source, limit))
        self.assertEqual(
            {"source_key", "external_id", "expected_fingerprint", "request_id", "requester"},
            set(payload),
        )
        self.assertEqual("admin", payload["requester"])
        self.assertNotIn(TOKEN, repr(payload))
        self.assertNotIn(ADMIN_TOKEN, repr(payload))

    def test_csrf_rejects_cross_origin_and_fetch_metadata_but_bearer_api_remains_separate(self):
        self._login()
        page = self.client.get("/explorer")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
        denied_origin = self.client.post(
            "/explorer/search",
            data={"_csrf": csrf, "provider_key": "misp", "query": "test"},
            headers={"Origin": "https://evil.example"},
        )
        denied_fetch = self.client.post(
            "/explorer/search",
            data={"_csrf": csrf, "provider_key": "misp", "query": "test"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(403, denied_origin.status_code)
        self.assertEqual(403, denied_fetch.status_code)

    def test_opaque_origin_requires_same_origin_fetch_metadata_and_csrf_token(self):
        client = TestClient(self.app, base_url="https://testserver")
        page = client.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
        payload = {"_csrf": csrf, "username": "reader", "password": READER_PASSWORD}

        allowed = client.post(
            "/login",
            data=payload,
            headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
            follow_redirects=False,
        )

        invalid_token_client = TestClient(self.app, base_url="https://testserver")
        invalid_page = invalid_token_client.get("/login")
        invalid_csrf = re.search(
            r'name="_csrf" value="([^"]+)"', invalid_page.text
        ).group(1)
        invalid_payload = {**payload, "_csrf": f"{invalid_csrf}-invalid"}
        denied_invalid_token = invalid_token_client.post(
            "/login",
            data=invalid_payload,
            headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
            follow_redirects=False,
        )

        cross_site_client = TestClient(self.app, base_url="https://testserver")
        cross_site_page = cross_site_client.get("/login")
        cross_site_csrf = re.search(
            r'name="_csrf" value="([^"]+)"', cross_site_page.text
        ).group(1)
        denied_cross_site = cross_site_client.post(
            "/login",
            data={**payload, "_csrf": cross_site_csrf},
            headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"},
            follow_redirects=False,
        )

        missing_metadata_client = TestClient(self.app, base_url="https://testserver")
        missing_metadata_page = missing_metadata_client.get("/login")
        missing_metadata_csrf = re.search(
            r'name="_csrf" value="([^"]+)"', missing_metadata_page.text
        ).group(1)
        denied_without_metadata = missing_metadata_client.post(
            "/login",
            data={**payload, "_csrf": missing_metadata_csrf},
            headers={"Origin": "null"},
            follow_redirects=False,
        )

        self.assertEqual(303, allowed.status_code)
        self.assertEqual(403, denied_invalid_token.status_code)
        self.assertEqual(403, denied_cross_site.status_code)
        self.assertEqual(403, denied_without_metadata.status_code)

    def test_reverse_proxy_origin_uses_explicit_public_origin_not_forwarded_headers(self):
        settings = WebSettings(
            credentials_file="synthetic-credentials-file",
            allowed_hosts=("testserver",),
            cookie_secure=False,
            public_origin="https://cti.example",
        )
        app = create_web_app(
            settings,
            source_explorer=self.explorer,
            credential_store=self.credential_store,
            operator_store=self.operator_store,
            operator_authenticator=self.operator_authenticator,
            review_api_app=self.review_api_app,
            session_store=InMemoryWebSessionStore(300, 3600),
            job_repository=self.jobs,
        )
        client = TestClient(app, base_url="http://testserver")
        self._login(client)
        page = client.get("/explorer")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)

        allowed = client.post(
            "/explorer/search",
            data={"_csrf": csrf, "provider_key": "misp", "query": "test"},
            headers={
                "Origin": "https://cti.example",
                "Sec-Fetch-Site": "same-origin",
                "X-Forwarded-Proto": "https",
            },
        )
        denied = client.post(
            "/explorer/search",
            data={"_csrf": csrf, "provider_key": "misp", "query": "test"},
            headers={"Origin": "https://evil.example", "X-Forwarded-Proto": "https"},
        )
        self.assertEqual(200, allowed.status_code)
        self.assertEqual(403, denied.status_code)

    def test_existing_review_api_remains_bearer_authenticated_and_is_mounted_at_same_path(self):
        denied = self.client.get("/api/v1/review/summary")
        self.assertEqual(denied.status_code, 401)
        allowed = self.client.get("/api/v1/review/summary", headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.json(), {"pending": 0, "released": 0})

    def test_review_health_contract_docs_and_security_headers_survive_web_composition(self):
        api = create_review_api_app(
            settings=ReviewApiSettings(
                repository_file="synthetic-quarantine",
                release_audit_file="synthetic-audit",
                credentials_file="synthetic-credentials-file",
                allowed_hosts=("testserver",),
                docs_enabled=True,
            ),
            review_service=_ReviewService(),
            credential_store=self.credential_store,
        )
        client = TestClient(create_web_app(
            self.settings,
            source_explorer=self.explorer,
            credential_store=self.credential_store,
            operator_store=self.operator_store,
            operator_authenticator=self.operator_authenticator,
            review_api_app=api,
            session_store=InMemoryWebSessionStore(300, 3600),
            job_repository=self.jobs,
        ), base_url="https://testserver")
        health = client.get("/healthz")
        self.assertEqual(200, health.status_code)
        self.assertEqual({"status": "ok", "service": "narrowcti-review-api"}, health.json())
        self.assertEqual("nosniff", health.headers["x-content-type-options"])
        self.assertEqual(200, client.get("/openapi.json").status_code)
        self.assertEqual(200, client.get("/docs").status_code)

    def test_overview_evidence_and_report_inventory_are_safe_and_accessible(self):
        self._login()
        overview = self.client.get("/")
        self.assertIn("Quarantine", overview.text)
        self.assertIn("Synthetic event", overview.text)
        self.assertIn('aria-current="page"', overview.text)
        evidence = self.client.get("/evidence")
        self.assertEqual(200, evidence.status_code)
        self.assertIn("Synthetic event", evidence.text)
        self.assertNotIn("evidence-secret-canary", evidence.text)
        self.assertNotIn("C:/private/audit.jsonl", evidence.text)
        reports = self.client.get("/reports")
        self.assertEqual(200, reports.status_code)
        self.assertIn("Available to operators", reports.text)
        self.assertNotIn("gateway.decisions", reports.text)
        self.assertIn("does not generate files", reports.text)

    def test_community_ia_routes_use_approved_access_and_preserve_legacy_paths(self):
        self._login()
        expected = {
            "/": "Overview",
            "/sources": "Sources",
            "/explorer": "Source Explorer",
            "/decisions": "Decisions",
            "/review": "Quarantine review",
            "/evidence": "Decision Audit",
            "/evidence/operational": "Operational Evidence",
            "/evidence/validation": "Operational Validation",
            "/reports": "Reports",
            "/system/health": "Health / Preflight",
            "/system/providers": "Providers",
            "/system/capabilities": "Community capabilities",
            "/account": "My account",
        }
        for path, marker in expected.items():
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assertIn(marker, response.text)
                self.assertIn("content-security-policy", response.headers)
        self.assertEqual(200, self.client.get("/healthz").status_code)
        self.assertEqual(404, self.client.get("/quarantine").status_code)
        self.assertEqual(401, self.client.get("/api/v1/review/summary").status_code)

    def test_operational_pages_strip_paths_secrets_and_raw_report_messages(self):
        self._login()
        for path in ("/system/health", "/evidence/operational", "/evidence/validation"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assertNotIn("C:/private", response.text)
                self.assertNotIn("secret-canary", response.text)
        health = self.client.get("/system/health")
        self.assertIn("Hybrid", health.text)
        self.assertIn("mitre-cache-missing", health.text)
        validation = self.client.get("/evidence/validation")
        self.assertIn("Authoritative validation sources: misp", validation.text)
        self.assertNotIn("otx", validation.text)
        self.assertNotIn("Healthy", self.client.get("/system/providers").text)
        self.assertNotIn("Reachable", self.client.get("/system/providers").text)
        capabilities = self.client.get("/system/capabilities")
        self.assertIn("source explorer", capabilities.text.lower())
        self.assertIn("Community web workspace", capabilities.text)
        self.assertIn("Use the authenticated Community web interface.", capabilities.text)
        self.assertIn("<code class=\"muted\">ui.basic</code>", capabilities.text)
        self.assertNotIn("Ui Basic", capabilities.text)
        self.assertNotIn("scheduler", capabilities.text.lower())

    def test_brand_logo_display_contract_is_exclusive_for_expanded_collapsed_and_mobile(self):
        css = (
            Path(__file__).parents[1]
            / "src/narrowcti/api/web/static/app.css"
        ).read_text(encoding="utf-8")
        template = (
            Path(__file__).parents[1]
            / "src/narrowcti/api/web/templates/base.html"
        ).read_text(encoding="utf-8")
        self.assertIn("narrowcti-logo-horizontal-dark.svg", template)
        self.assertIn("narrowcti-symbol-gradient.svg", template)
        self.assertRegex(css, r"\.brand \.brand-expanded\s*\{\s*display:\s*block;")
        self.assertRegex(css, r"\.brand \.brand-collapsed\s*\{\s*display:\s*none;")
        self.assertRegex(css, r"\.app-layout:has\(\.sidebar-toggle:checked\) \.brand-expanded[^\{]*\{\s*display:\s*none;")
        self.assertRegex(css, r"\.app-layout:has\(\.sidebar-toggle:checked\) \.brand-collapsed[^\{]*\{\s*display:\s*block;")
        self.assertRegex(css, r"@media \(max-width: 800px\)[\s\S]*?\.brand \.brand-expanded\s*\{\s*display:\s*none !important;")
        self.assertRegex(css, r"@media \(max-width: 800px\)[\s\S]*?\.brand \.brand-collapsed\s*\{\s*display:\s*block !important;")

    def test_mid_sized_workspace_reflows_explorer_and_review_filters(self):
        css = (Path(__file__).parents[1] / "src/narrowcti/api/web/static/app.css").read_text(encoding="utf-8")
        self.assertRegex(
            css,
            r"@media \(max-width: 1100px\)[\s\S]*?\.explorer-toolbar \{ grid-template-columns: minmax\(140px, \.7fr\) minmax\(220px, 2fr\); \}",
        )
        self.assertRegex(
            css,
            r"@media \(max-width: 1100px\)[\s\S]*?\.queue-filters \{ grid-template-columns: auto minmax\(0, 1fr\) auto minmax\(0, 1fr\); \}",
        )

    def test_gateway_publishes_authoritative_snapshot_from_raw_graph_evidence(self):
        audit_dir = Path(self._temporary.name) / "gateway-audit"
        audit_dir.mkdir()
        audit_record = {
            "recorded_at": "2026-09-28T12:00:00Z", "source_key": "misp",
            "query": "tlp:green", "action": "dry-run", "reason": "candidate evaluated",
            "score": 90, "metadata": {
                "graph_export_plan": {
                    "mode": "dry-run", "status": "dry-run", "candidate_count": 1,
                    "accepted_count": 1, "accepted_object_counts": {"attack-pattern": 1},
                },
                "graph_export_plan_lookup_matches": [{
                    "stix_object_type": "attack-pattern",
                    "match": {"match_type": "mitre_attack_id", "entity_type": "Attack-Pattern"},
                }],
            },
        }
        with (audit_dir / "misp.jsonl").open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(audit_record) + "\n")
        gateway_env = {
            "NARROWCTI_STATE_DIR": str(Path(self._temporary.name) / "gateway-state"),
            "NARROWCTI_RUNTIME_DB": self.settings.runtime_db_file,
            "NARROWCTI_DECISION_AUDIT_DIR": str(audit_dir),
            "NARROWCTI_ENABLED_SOURCES": "otx,misp",
            "NARROWCTI_OPERATIONAL_VALIDATION_SOURCES": "misp",
            "NARROWCTI_GRAPH_EXPORT_MODE": "dry-run",
            "NARROWCTI_GRAPH_DEDUP_STATE_FILE": str(Path(self._temporary.name) / "graph-index.json"),
            "NARROWCTI_OPENCTI_GRAPH_LOOKUP": "true",
            "MISP_DRY_RUN": "true",
            "MISP_VERIFY_TLS": "true",
            "MISP_URL": "https://misp.example.invalid",
            "OPENCTI_URL": "https://opencti.example.invalid",
        }
        gateway_settings = load_gateway_settings(gateway_env)
        preflight = build_preflight_report(gateway_settings, env=gateway_env)
        preflight_snapshot = publish_gateway_preflight_snapshot(gateway_settings, preflight)
        records = read_decision_records([str(audit_dir)])
        decisions = build_decision_audit_report(records)
        validation_report = build_operational_validation_report(
            preflight,
            decisions,
            full_validation_passed=True,
            required_sources=gateway_settings.operational_validation_sources,
            relationship_audit_evidence={
                "found": True,
                "relationship_count": 3,
                "outbound_count": 2,
                "inbound_count": 1,
                "diamond_quadrant_counts": {"capability": 2, "infrastructure": 1},
                "kill_chain_attack_patterns": ["T1059"],
            },
        )
        validation_snapshot = publish_operational_validation_snapshot(
            gateway_settings,
            validation_report,
            gateway_settings.operational_validation_sources,
        )
        checks = {check["code"]: check["status"] for check in validation_snapshot.report["checks"]}
        self.assertEqual("pass", checks["canonical-attack-match"])
        self.assertEqual("pass", checks["lookup-metadata"])
        self.assertEqual(("otx", "misp"), preflight.enabled_sources)
        self.assertEqual(("misp",), gateway_settings.operational_validation_sources)
        self.assertEqual(("misp",), validation_snapshot.required_sources)
        self.assertEqual("pass", checks["full-validation"])
        self.assertEqual("pass", checks["opencti-relationship-audit"])

        store = LocalOperationalSnapshotStore(self.settings.runtime_db_file)
        published_preflight = store.read_preflight()
        published_validation = store.read_validation()
        self.assertIsNotNone(published_preflight)
        self.assertIsNotNone(published_validation)
        self.assertEqual(preflight_snapshot.to_dict(), published_preflight)
        self.assertEqual(["misp"], published_validation["required_sources"])
        serialized = json.dumps([published_preflight, published_validation])
        self.assertNotIn("misp.example.invalid", serialized)
        self.assertNotIn("opencti.example.invalid", serialized)
        self.assertNotIn(str(audit_dir), serialized)
        self.assertNotIn("graph-index.json", serialized)

        client = TestClient(create_web_app(
            self.settings,
            source_explorer=self.explorer,
            credential_store=self.credential_store,
            operator_store=self.operator_store,
            operator_authenticator=self.operator_authenticator,
            review_api_app=self.review_api_app,
            session_store=InMemoryWebSessionStore(300, 3600),
            job_repository=self.jobs,
        ), base_url="https://testserver")
        self._login(client=client)
        response = client.get("/evidence/validation")
        self.assertEqual(200, response.status_code)
        self.assertIn("Authoritative validation sources: misp", response.text)
        self.assertNotIn("otx", response.text)
        self.assertIn("Canonical Attack Match", response.text)
        self.assertNotIn("opencti.example.invalid", response.text)

    def test_web_role_env_cannot_manufacture_gateway_state_without_snapshot(self):
        web_settings = load_web_settings({
            "NARROWCTI_AUTH_DB": str(Path(self._temporary.name) / "auth.db"),
            "NARROWCTI_RUNTIME_DB": str(Path(self._temporary.name) / "missing-runtime.db"),
            "NARROWCTI_WEB_ALLOWED_HOSTS": "testserver",
            "NARROWCTI_WEB_COOKIE_SECURE": "false",
            "NARROWCTI_GRAPH_EXPORT_MODE": "export",
            "NARROWCTI_ENABLED_SOURCES": "otx,misp",
            "MISP_VERIFY_TLS": "false",
        })
        client = TestClient(create_web_app(
            web_settings,
            source_explorer=self.explorer,
            credential_store=self.credential_store,
            operator_store=self.operator_store,
            operator_authenticator=self.operator_authenticator,
            review_api_app=self.review_api_app,
            session_store=InMemoryWebSessionStore(300, 3600),
            job_repository=self.jobs,
        ), base_url="https://testserver")
        self._login(client=client)
        self.assertEqual(str(Path(self._temporary.name) / "missing-runtime.db"), web_settings.runtime_db_file)
        response = client.get("/system/health")
        self.assertEqual(200, response.status_code)
        self.assertIn("Authoritative preflight snapshot unavailable", response.text)
        self.assertIn("rerun the authoritative preflight workflow", response.text)
        self.assertNotIn("Export", response.text)
        validation = client.get("/evidence/validation")
        self.assertIn("Authoritative Operational Validation snapshot unavailable", validation.text)
        self.assertIn("rerun Operational Validation from the Gateway/Ops role", validation.text)

    def test_stale_authoritative_snapshots_show_capture_time_and_refresh_guidance(self):
        self._login()
        captured_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        target_app = self.client.app
        while not hasattr(target_app, "state"):
            target_app = target_app.app
        target_app.state.operational_state_reader = _SnapshotReader(
            preflight={
                "schema": "narrowcti.web-preflight/v1",
                "captured_at": captured_at,
                "report": {"status": "ready", "sources": [], "issues": []},
            },
            validation={
                "schema": "narrowcti.web-operational-validation/v1",
                "captured_at": captured_at,
                "required_sources": ["misp"],
                "report": {
                    "status": "needs-evidence",
                    "checks": [],
                    "counts": {"needs-evidence": 1},
                },
            },
        )

        preflight = self.client.get("/system/health")
        self.assertEqual(200, preflight.status_code)
        self.assertIn("Stale snapshot", preflight.text)
        self.assertIn(captured_at, preflight.text)
        self.assertIn("Ask a Gateway operator to rerun the authoritative preflight workflow", preflight.text)

        validation = self.client.get("/evidence/validation")
        self.assertEqual(200, validation.status_code)
        self.assertIn("Stale snapshot", validation.text)
        self.assertIn(captured_at, validation.text)
        self.assertIn("with its manual and relationship evidence inputs", validation.text)

    def test_browser_http_errors_are_autoescaped_html_with_status_and_security_headers(self):
        self._login()

        def hostile_detail(_provider_key, _external_id):
            raise ExplorerError("source_not_found", "<script>synthetic-xss</script>")

        self.explorer.detail = hostile_detail
        response = self.client.get("/explorer/misp/42")
        self.assertEqual(404, response.status_code)
        self.assertEqual("text/html; charset=utf-8", response.headers["content-type"])
        self.assertNotIn("<script>synthetic-xss</script>", response.text)
        self.assertIn("&lt;script&gt;synthetic-xss&lt;/script&gt;", response.text)
        self.assertEqual("DENY", response.headers["x-frame-options"])
        self.assertIn('class="app-layout"', response.text)
        self.assertIn('aria-label="My Account"', response.text)
        self.assertIn('aria-label="Sign out"', response.text)

    def test_error_page_preserves_authenticated_or_anonymous_shell_and_exception_headers(self):
        from fastapi import HTTPException

        async def failure():
            raise HTTPException(status_code=409, detail="<unsafe>", headers={"X-Contract": "preserved"})

        inner_app = self.app.app.app.app
        inner_app.add_api_route("/test-http-error", failure)
        from starlette.routing import Mount
        test_route = inner_app.router.routes.pop()
        review_mount = next(index for index, route in enumerate(inner_app.router.routes) if isinstance(route, Mount) and route.path == "")
        inner_app.router.routes.insert(review_mount, test_route)
        self._login()
        authenticated = self.client.get("/test-http-error")
        self.assertEqual(409, authenticated.status_code)
        self.assertEqual("preserved", authenticated.headers["x-contract"])
        self.assertIn('class="app-layout"', authenticated.text)
        self.assertIn("&lt;unsafe&gt;", authenticated.text)
        self.client.cookies.clear()
        anonymous = self.client.get("/test-http-error")
        self.assertEqual(409, anonymous.status_code)
        self.assertIn('class="login-shell"', anonymous.text)
        self.assertNotIn('class="app-layout"', anonymous.text)

    def test_mobile_menu_keeps_account_and_sign_out_controls_in_expanded_navigation(self):
        self._login()
        page = self.client.get("/")
        self.assertIn('id="sidebar-toggle"', page.text)
        self.assertIn('class="mobile-label mobile-open-label">Menu</span>', page.text)
        self.assertIn('class="mobile-close-label">Close</span>', page.text)
        self.assertIn('aria-label="My Account"', page.text)
        self.assertIn('aria-label="Sign out"', page.text)
        css = self.client.get("/assets/app.css").text
        self.assertIn("@media (max-width: 800px)", css)
        mobile_css = css.split("@media (max-width: 800px)", 1)[1].split("@media (max-width: 640px)", 1)[0]
        self.assertIn(".sidebar:has(.sidebar-toggle:checked) .sidebar-account { display: grid", mobile_css)
        self.assertIn(".sidebar:has(.sidebar-toggle:checked) .sidebar-nav .nav-label { display: inline; }", mobile_css)
        self.assertIn(".sidebar:has(.sidebar-toggle:checked) .sidebar-nav .nav-section { display: block; }", mobile_css)
        self.assertIn(".sidebar:has(.sidebar-toggle:checked) .sidebar-nav .nav-link { justify-content: flex-start;", mobile_css)
        self.assertIn(".sidebar:has(.sidebar-toggle:checked) .mobile-open-label { display: none; }", mobile_css)
        self.assertIn(".sidebar:has(.sidebar-toggle:checked) .mobile-close-label { display: inline; }", mobile_css)
        self.assertIn(".brand .brand-collapsed { display: block !important;", mobile_css)

    def test_quarantine_queue_filters_and_contextual_actions_preserve_permissions(self):
        self.review_service.records = [
            {"quarantine_id": "q-1", "title": "Lazarus campaign", "source_key": "misp", "external_id": "822", "reason": "manual review", "status": "pending", "indicator_count": 4, "created_at": "2026-09-28T10:00:00Z"},
            {"quarantine_id": "q-2", "title": "Other campaign", "source_key": "otx", "external_id": "99", "reason": "other", "status": "pending", "indicator_count": 1, "created_at": "2026-09-27T10:00:00Z"},
        ]
        self._login(token=ADMIN_TOKEN)
        response = self.client.get("/review?status=pending&source=misp&q=lazarus")
        self.assertEqual(200, response.status_code)
        self.assertIn("Review queue", response.text)
        self.assertIn("Lazarus campaign", response.text)
        self.assertNotIn("Other campaign", response.text)
        self.assertIn("Release all", response.text)
        self.assertIn("Reject", response.text)
        self.assertIn("Inspect", response.text)

    def test_web_security_headers_and_source_cannot_set_secure_cookie_name(self):
        self.assertNotEqual(SESSION_COOKIE_LOCAL, SESSION_COOKIE_SECURE)
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-security-policy"].split(";")[0], "default-src 'none'")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_body_limit_host_validation_and_invalid_session_are_enforced(self):
        oversized = self.client.post(
            "/explorer/search",
            content=b"x" * (self.settings.max_request_body_bytes + 1),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(oversized.status_code, 413)
        self.assertIn("default-src 'none'", oversized.headers["content-security-policy"])

        invalid_session = self.client.get(
            "/explorer",
            headers={"cookie": f"{SESSION_COOKIE_LOCAL}=invalid-session"},
            follow_redirects=False,
        )
        self.assertEqual(invalid_session.status_code, 303)
        self.assertEqual(invalid_session.headers["location"], "/login")

        invalid_host = self.client.get("/healthz", headers={"host": "evil.example"})
        self.assertEqual(invalid_host.status_code, 400)

    def test_job_page_projects_only_stable_error_codes(self):
        self._login()
        self.jobs.jobs["synthetic-key"] = {
            "job_id": "job-secret-test",
            "job_type": "ingestion.run_once",
            "payload": {"requester": "reader"},
            "status": "failed",
            "created_at": "2026-01-01T00:00:00Z",
            "error": "provider response included synthetic-secret-value",
            "result": None,
        }

        response = self.client.get("/jobs/job-secret-test")

        self.assertEqual(response.status_code, 200)
        self.assertIn("job_failed", response.text)
        self.assertNotIn("synthetic-secret-value", response.text)

    def test_valid_csrf_with_unsupported_body_encoding_is_rejected(self):
        self._login()
        page = self.client.get("/explorer")
        csrf = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)

        response = self.client.post(
            "/explorer/search",
            content='{"_csrf":"%s"}' % csrf,
            headers={"content-type": "application/json", "x-csrf-token": csrf},
        )

        self.assertEqual(response.status_code, 415)


if __name__ == "__main__":
    unittest.main()
