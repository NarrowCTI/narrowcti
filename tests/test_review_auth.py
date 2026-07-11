import json
import os
import tempfile
import unittest

from gateway.review_auth import (
    ReviewCredentialStore,
    generate_token,
    normalize_credentials,
    token_sha256,
)


class ReviewAuthenticationTests(unittest.TestCase):
    def test_loads_hashed_credentials_and_authenticates_token(self):
        token = "reader-token-that-is-at-least-32-characters"
        document = {
            "credentials": [
                {
                    "credential_id": "reader-key",
                    "principal": "analyst@example.org",
                    "token_sha256": token_sha256(token),
                    "roles": ["reader"],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "credentials.json")
            with open(path, "w", encoding="utf-8") as file_obj:
                json.dump(document, file_obj)

            store = ReviewCredentialStore.from_file(path)

        principal = store.authenticate(token)
        self.assertEqual("analyst@example.org", principal.principal)
        self.assertEqual("reader-key", principal.credential_id)
        self.assertTrue(principal.has_permission("review:read"))
        self.assertFalse(principal.has_permission("review:decide"))
        self.assertIsNone(store.authenticate("wrong-token"))

    def test_rejects_duplicate_hashes_and_unknown_roles(self):
        token_hash = token_sha256("x" * 32)
        duplicate = {
            "principal": "analyst",
            "token_sha256": token_hash,
            "roles": ["reader"],
        }
        with self.assertRaisesRegex(ValueError, "duplicate"):
            normalize_credentials([duplicate, duplicate])
        with self.assertRaisesRegex(ValueError, "unknown roles"):
            normalize_credentials(
                [
                    {
                        "principal": "analyst",
                        "token_sha256": token_hash,
                        "roles": ["owner"],
                    }
                ]
            )

    def test_admin_has_all_permissions(self):
        store = ReviewCredentialStore(
            normalize_credentials(
                [
                    {
                        "principal": "admin",
                        "token_sha256": token_sha256("a" * 32),
                        "roles": ["admin"],
                    }
                ]
            )
        )

        principal = store.authenticate("a" * 32)

        self.assertTrue(principal.has_permission("review:raw"))
        self.assertTrue(principal.has_permission("export:execute"))

    def test_generated_token_is_long_and_matches_hash(self):
        token, token_hash = generate_token()

        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(token_sha256(token), token_hash)


if __name__ == "__main__":
    unittest.main()
