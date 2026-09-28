"""Provision deployment-managed Community Web operator accounts."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from narrowcti.adapters.persistence.local.operator_store import (
    LocalOperatorStore,
    OperatorNotFound,
    OperatorStoreError,
)
from narrowcti.application.identity.passwords import PasswordPolicyError, PasswordService
from narrowcti.infrastructure.config.web_settings import load_web_settings


def _password(*, from_stdin: bool) -> str:
    if from_stdin:
        value = sys.stdin.readline(1027)
        if not value or len(value) > 1026 or ("\n" not in value and len(value) > 1024):
            raise ValueError("password input is missing or too long")
        if value.endswith("\n"):
            value = value[:-1]
        if value.endswith("\r"):
            value = value[:-1]
        if "\n" in value or "\r" in value:
            raise ValueError("password input must contain exactly one line")
        if sys.stdin.read(1):
            raise ValueError("password input must contain exactly one line")
        if len(value.encode("utf-8")) > 1024:
            raise ValueError("password must not exceed 1024 UTF-8 bytes")
        return value
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise ValueError("passwords do not match")
    return first


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage local NarrowCTI Community operators.")
    parser.add_argument("--db", help="operator database path (defaults to NARROWCTI_AUTH_DB)")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create-operator", help="create a local operator")
    create.add_argument("--username", required=True)
    create.add_argument("--role", action="append", required=True, dest="roles")
    create.add_argument("--password-stdin", action="store_true")

    commands.add_parser("list-operators", help="list local operators without credential data")

    password = commands.add_parser("set-password", help="set an operator password")
    password.add_argument("--username", required=True)
    password.add_argument("--password-stdin", action="store_true")

    roles = commands.add_parser("set-roles", help="replace an operator's roles")
    roles.add_argument("--username", required=True)
    roles.add_argument("--role", action="append", required=True, dest="roles")

    for name in ("enable", "disable"):
        command = commands.add_parser(name, help=f"{name} a local operator")
        command.add_argument("--username", required=True)
    return parser


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if any(item == "--password" or item.startswith("--password=") for item in arguments):
        print("plaintext password arguments are unsupported; use --password-stdin", file=sys.stderr)
        return 2
    args = _build_parser().parse_args(arguments)
    try:
        settings = load_web_settings()
        database_path = args.db or settings.auth_db
        if Path(database_path).resolve() == Path(settings.runtime_db_file).resolve():
            raise ValueError("operator authentication database must be separate from runtime.db")
        store = LocalOperatorStore(database_path)
        if args.command == "create-operator":
            passwords = PasswordService()
            raw_password = _password(from_stdin=args.password_stdin)
            try:
                record = store.create_operator(
                    args.username,
                    passwords.hash_password(raw_password),
                    args.roles,
                )
            finally:
                raw_password = ""
            print(f'Operator "{record.username}" created. Roles: {", ".join(sorted(record.roles))}')
        elif args.command == "list-operators":
            for record in store.list_operators():
                status = "enabled" if record.enabled else "disabled"
                print(f'{record.username}\t{status}\t{", ".join(sorted(record.roles))}')
        elif args.command == "set-password":
            passwords = PasswordService()
            record = store.get_by_username(args.username)
            if record is None:
                raise OperatorNotFound("operator was not found")
            raw_password = _password(from_stdin=args.password_stdin)
            try:
                store.set_password_hash(record.operator_id, passwords.hash_password(raw_password))
            finally:
                raw_password = ""
            print(f'Password updated for "{record.username}". Existing Web sessions are invalidated.')
        elif args.command == "set-roles":
            record = store.get_by_username(args.username)
            if record is None:
                raise OperatorNotFound("operator was not found")
            updated = store.set_roles(record.operator_id, args.roles)
            print(f'Roles updated for "{updated.username}". Existing Web sessions are invalidated.')
        else:
            record = store.get_by_username(args.username)
            if record is None:
                raise OperatorNotFound("operator was not found")
            updated = store.set_enabled(record.operator_id, args.command == "enable")
            print(f'Operator "{updated.username}" {"enabled" if updated.enabled else "disabled"}.')
    except (ValueError, PasswordPolicyError, OperatorStoreError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
