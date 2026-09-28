"""HTTP contracts for browser sessions, CSRF, Source Explorer and API coexistence."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from narrowcti.api.review.app import ReviewApiSettings, create_app as create_review_api_app
from narrowcti.api.review.auth import ReviewCredentialStore, token_sha256
from narrowcti.api.web.app import SESSION_COOKIE_LOCAL, SESSION_COOKIE_SECURE, create_web_app
from narrowcti.infrastructure.config.web_settings import WebSettings
from narrowcti.api.web.sessions import InMemoryWebSessionStore
from narrowcti.adapters.persistence.local.operator_store import LocalOperatorStore
from narrowcti.application.identity.passwords import LocalOperatorAuthenticator, PasswordService
from narrowcti.application.reporting.web_evidence import WebEvidenceService
from narrowcti.ports.source_explorer import (
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
    def summary(self):
        return _Summary()


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
        api = create_review_api_app(
            settings=ReviewApiSettings(
                repository_file="synthetic-quarantine",
                release_audit_file="synthetic-audit",
                credentials_file="synthetic-credentials-file",
                allowed_hosts=("testserver", "localhost"),
            ),
            review_service=_ReviewService(),
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
        self.assertIn("Quarantine status", overview.text)
        self.assertIn('aria-current="page"', overview.text)
        evidence = self.client.get("/evidence")
        self.assertEqual(200, evidence.status_code)
        self.assertIn("Synthetic event", evidence.text)
        self.assertNotIn("evidence-secret-canary", evidence.text)
        self.assertNotIn("C:/private/audit.jsonl", evidence.text)
        reports = self.client.get("/reports")
        self.assertEqual(200, reports.status_code)
        self.assertIn("Not generated", reports.text)
        self.assertIn("does not generate files", reports.text)

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
