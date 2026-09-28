"""Server-side browser session lifetime and secret-retention contracts."""

from __future__ import annotations

import unittest

from narrowcti.api.review.auth import ReviewPrincipal
from narrowcti.api.web.sessions import InMemoryWebSessionStore


class InMemoryWebSessionStoreTests(unittest.TestCase):
    def test_anonymous_session_rotates_on_authentication_and_stores_no_bearer(self):
        now = [1000.0]
        store = InMemoryWebSessionStore(60, 120, clock=lambda: now[0])
        old_id, anonymous = store.create_anonymous()
        principal = ReviewPrincipal("analyst", frozenset({"reader"}), "reader-1")

        new_id, authenticated = store.authenticate(old_id, principal)

        self.assertNotEqual(old_id, new_id)
        self.assertIsNone(store.get(old_id))
        self.assertIs(store.get(new_id).principal, principal)
        self.assertNotIn("bearer", repr(authenticated).lower())
        self.assertNotEqual(anonymous.csrf_token, authenticated.csrf_token)

    def test_idle_and_absolute_expiration_are_enforced(self):
        now = [100.0]
        store = InMemoryWebSessionStore(60, 120, clock=lambda: now[0])
        session_id, _ = store.create_anonymous()

        now[0] = 159.0
        self.assertIsNotNone(store.get(session_id))
        now[0] = 220.0
        self.assertIsNone(store.get(session_id))

        session_id, _ = store.create_anonymous()
        now[0] = 340.0
        self.assertIsNone(store.get(session_id))

    def test_delete_is_idempotent(self):
        store = InMemoryWebSessionStore(60, 120, clock=lambda: 100.0)
        session_id, _ = store.create_anonymous()
        store.delete(session_id)
        store.delete(session_id)
        self.assertEqual(len(store), 0)


if __name__ == "__main__":
    unittest.main()
