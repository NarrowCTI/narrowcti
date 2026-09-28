"""Safe deployment-managed operator CLI contracts."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from narrowcti.adapters.persistence.local.operator_store import LocalOperatorStore
from narrowcti.application.identity.passwords import LocalOperatorAuthenticator
from narrowcti.cli.auth import main


class OperatorCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "auth.db"

    def _run_stdin(self, argv, value):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(value)), redirect_stdout(output):
            result = main(["--db", str(self.db), *argv, "--password-stdin"])
        self.assertEqual(0, result)
        self.assertNotIn(value.strip(), output.getvalue())
        return output.getvalue()

    def test_create_list_and_set_password_without_printing_secret(self):
        first = self._run_stdin(
            ["create-operator", "--username", "firstadmin", "--role", "admin"],
            "synthetic first admin passphrase\n",
        )
        self.assertIn('Operator "firstadmin" created.', first)
        self._run_stdin(
            ["set-password", "--username", "firstadmin"],
            "synthetic replacement admin passphrase\n",
        )
        listed = io.StringIO()
        with redirect_stdout(listed):
            self.assertEqual(0, main(["--db", str(self.db), "list-operators"]))
        self.assertEqual("firstadmin\tenabled\tadmin", listed.getvalue().strip())
        store = LocalOperatorStore(self.db)
        record = store.get_by_username("firstadmin")
        auth = LocalOperatorAuthenticator(store)
        self.assertIsNone(auth.authenticate("firstadmin", "synthetic first admin passphrase"))
        self.assertIsNotNone(auth.authenticate("firstadmin", "synthetic replacement admin passphrase"))
        self.assertEqual(2, record.auth_revision)

    def test_interactive_password_confirmation_is_required(self):
        output = io.StringIO()
        with patch("narrowcti.cli.auth.getpass.getpass", side_effect=["synthetic passphrase one", "synthetic passphrase two"]), redirect_stderr(output):
            result = main(["--db", str(self.db), "create-operator", "--username", "admin", "--role", "admin"])
        self.assertEqual(2, result)
        self.assertIn("passwords do not match", output.getvalue())
        self.assertFalse(LocalOperatorStore(self.db).has_operators())

    def test_plaintext_password_argument_is_rejected_without_echo(self):
        secret = "synthetic plaintext secret"
        output = io.StringIO()
        with redirect_stderr(output):
            result = main([
                "create-operator", "--username", "admin", "--role", "admin",
                "--password", secret,
            ])
        self.assertEqual(2, result)
        self.assertIn("--password-stdin", output.getvalue())
        self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    unittest.main()
