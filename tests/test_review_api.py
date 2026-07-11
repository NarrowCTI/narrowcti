import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from core.quarantine import QuarantineRecord, QuarantineRepository
from gateway.review import AnalystReviewService
from gateway.review_api import ReviewApiSettings, create_app
from gateway.review_auth import (
    ReviewCredentialStore,
    normalize_credentials,
    token_sha256,
)


TOKENS = {
    "reader": "reader-token-that-is-at-least-32-characters",
    "reviewer": "reviewer-token-that-is-at-least-32-characters",
    "exporter": "exporter-token-that-is-at-least-32-characters",
    "admin": "admin-token-that-is-at-least-32-characters",
}


def credential_store():
    return ReviewCredentialStore(
        normalize_credentials(
            [
                {
                    "principal": f"{role}-principal",
                    "token_sha256": token_sha256(token),
                    "roles": [role],
                }
                for role, token in TOKENS.items()
            ]
        )
    )


def auth(role):
    return {"Authorization": f"Bearer {TOKENS[role]}"}


class FakeExportResult:
    def to_dict(self):
        return {"action": "export", "dry_run": False}


class RecordingExportService:
    def __init__(self):
        self.export_arguments = None

    def export_released(self, quarantine_id, **kwargs):
        self.export_arguments = {"quarantine_id": quarantine_id, **kwargs}
        return [FakeExportResult()]


class ReviewApiTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        repository_path = os.path.join(self.tmpdir.name, "quarantine.jsonl")
        audit_path = os.path.join(self.tmpdir.name, "releases.jsonl")
        self.repository = QuarantineRepository(repository_path, audit_path)
        self.record = self.repository.add(
            QuarantineRecord(
                source_key="misp",
                external_id="event-1",
                title="Controlled review event",
                reason="Needs analyst review",
                score=55,
                indicators=(
                    {"type": "domain", "indicator": "example.test"},
                    {"type": "ipv4", "indicator": "192.0.2.10"},
                ),
                raw_snapshot={"sensitive": "source payload"},
            )
        )
        settings = ReviewApiSettings(
            repository_file=repository_path,
            release_audit_file=audit_path,
            credentials_file="unused-in-tests.json",
            allow_export=False,
        )
        service = AnalystReviewService(
            self.repository,
            release_audit_file=audit_path,
            require_reason=True,
        )
        self.client = TestClient(
            create_app(
                settings=settings,
                review_service=service,
                credential_store=credential_store(),
            )
        )

    def tearDown(self):
        self.client.close()
        self.tmpdir.cleanup()

    def test_health_is_public_and_has_security_headers(self):
        response = self.client.get("/healthz")

        self.assertEqual(200, response.status_code)
        self.assertEqual("ok", response.json()["status"])
        self.assertEqual("no-store", response.headers["cache-control"])
        self.assertEqual("DENY", response.headers["x-frame-options"])

    def test_review_routes_require_bearer_authentication(self):
        response = self.client.get("/api/v1/review/summary")

        self.assertEqual(401, response.status_code)
        self.assertEqual("Bearer", response.headers["www-authenticate"])

    def test_rejects_untrusted_host_and_oversized_declared_body(self):
        untrusted = self.client.get("/healthz", headers={"Host": "evil.example"})
        headers = {**auth("reviewer"), "Content-Length": "20000"}
        oversized = self.client.post(
            f"/api/v1/review/records/{self.record['quarantine_id']}/reject",
            headers=headers,
            content=b"{}",
        )

        self.assertEqual(400, untrusted.status_code)
        self.assertEqual(413, oversized.status_code)

    def test_reader_can_list_but_cannot_decide(self):
        listed = self.client.get("/api/v1/review/records", headers=auth("reader"))
        rejected = self.client.post(
            f"/api/v1/review/records/{self.record['quarantine_id']}/reject",
            headers=auth("reader"),
            json={"reason": "Out of scope"},
        )

        self.assertEqual(200, listed.status_code)
        self.assertEqual(1, listed.json()["count"])
        self.assertNotIn("raw_snapshot", listed.json()["items"][0])
        self.assertEqual(403, rejected.status_code)

    def test_admin_must_explicitly_request_raw_snapshot(self):
        path = f"/api/v1/review/records/{self.record['quarantine_id']}"

        hidden = self.client.get(path, headers=auth("admin"))
        visible = self.client.get(
            f"{path}?include_raw=true",
            headers=auth("admin"),
        )
        denied = self.client.get(
            f"{path}?include_raw=true",
            headers=auth("reader"),
        )

        self.assertNotIn("raw_snapshot", hidden.json())
        self.assertEqual("source payload", visible.json()["raw_snapshot"]["sensitive"])
        self.assertEqual(403, denied.status_code)

    def test_reviewer_identity_comes_from_authenticated_credential(self):
        response = self.client.post(
            f"/api/v1/review/records/{self.record['quarantine_id']}/release",
            headers=auth("reviewer"),
            json={"reason": "Relevant to monitored scope"},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual("released", response.json()["status"])
        self.assertEqual(
            "reviewer-principal",
            response.json()["review"]["reviewer"],
        )

    def test_blank_reason_and_extra_fields_are_rejected(self):
        path = f"/api/v1/review/records/{self.record['quarantine_id']}/reject"

        blank = self.client.post(
            path,
            headers=auth("reviewer"),
            json={"reason": "   "},
        )
        extra = self.client.post(
            path,
            headers=auth("reviewer"),
            json={"reason": "Out of scope", "reviewer": "spoofed"},
        )

        self.assertEqual(422, blank.status_code)
        self.assertEqual(422, extra.status_code)

    def test_partial_release_normalizes_and_deduplicates_types(self):
        response = self.client.post(
            f"/api/v1/review/records/{self.record['quarantine_id']}/release-indicators",
            headers=auth("reviewer"),
            json={
                "reason": "Release network evidence",
                "indicator_types": ["DOMAIN", "domain"],
            },
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual("partially-released", response.json()["status"])
        self.assertEqual(
            ["domain"],
            response.json()["review"]["released_indicator_types"],
        )

    def test_export_preview_is_dry_run_and_real_export_defaults_off(self):
        self.repository.release(
            self.record["quarantine_id"],
            "Relevant to monitored scope",
        )
        path = f"/api/v1/review/records/{self.record['quarantine_id']}"

        preview = self.client.post(
            f"{path}/export-preview",
            headers=auth("reviewer"),
        )
        execute = self.client.post(
            f"{path}/export",
            headers=auth("exporter"),
        )

        self.assertEqual(200, preview.status_code)
        self.assertTrue(preview.json()["items"][0]["dry_run"])
        self.assertEqual(403, execute.status_code)

    def test_unknown_record_is_not_found(self):
        response = self.client.get(
            "/api/v1/review/records/not-found",
            headers=auth("reader"),
        )

        self.assertEqual(404, response.status_code)

    def test_enabled_export_uses_authenticated_principal(self):
        service = RecordingExportService()
        settings = ReviewApiSettings(
            repository_file=os.path.join(self.tmpdir.name, "unused.jsonl"),
            release_audit_file=os.path.join(self.tmpdir.name, "unused-audit.jsonl"),
            credentials_file="unused-in-tests.json",
            allow_export=True,
        )
        client = TestClient(
            create_app(
                settings=settings,
                review_service=service,
                credential_store=credential_store(),
                opencti_client_factory=lambda: object(),
            )
        )
        try:
            response = client.post(
                "/api/v1/review/records/q-1/export",
                headers=auth("exporter"),
            )
        finally:
            client.close()

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            "review-api:exporter-principal",
            service.export_arguments["exported_by"],
        )
        self.assertFalse(service.export_arguments["dry_run"])


if __name__ == "__main__":
    unittest.main()
