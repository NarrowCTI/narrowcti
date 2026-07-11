import argparse
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass


VALID_ROLES = frozenset({"reader", "reviewer", "exporter", "admin"})
ROLE_PERMISSIONS = {
    "reader": frozenset({"review:read"}),
    "reviewer": frozenset({"review:read", "review:decide", "export:preview"}),
    "exporter": frozenset({"review:read", "export:preview", "export:execute"}),
    "admin": frozenset({"*"}),
}
PRINCIPAL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class ReviewPrincipal:
    principal: str
    roles: frozenset[str]
    credential_id: str = ""

    def has_permission(self, permission):
        granted = set()
        for role in self.roles:
            granted.update(ROLE_PERMISSIONS[role])
        return "*" in granted or permission in granted


class ReviewCredentialStore:
    def __init__(self, credentials):
        normalized = tuple(credentials)
        if not normalized:
            raise ValueError("at least one review API credential is required")
        self.credentials = normalized

    @classmethod
    def from_file(cls, path):
        if not path:
            raise ValueError("review API credentials file is required")
        try:
            with open(path, "r", encoding="utf-8-sig") as file_obj:
                document = json.load(file_obj)
        except OSError as exc:
            raise ValueError(f"cannot read review API credentials file: {exc}") from None
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid review API credentials JSON: {exc}") from None

        if not isinstance(document, dict) or not isinstance(
            document.get("credentials"), list
        ):
            raise ValueError("credentials file must contain a credentials list")
        return cls(normalize_credentials(document["credentials"]))

    def authenticate(self, token):
        if not isinstance(token, str) or len(token) < 32:
            return None
        candidate_hash = token_sha256(token)
        matched = None
        for credential in self.credentials:
            if hmac.compare_digest(candidate_hash, credential["token_sha256"]):
                matched = credential
        if not matched:
            return None
        return ReviewPrincipal(
            principal=matched["principal"],
            roles=matched["roles"],
            credential_id=matched["credential_id"],
        )


def normalize_credentials(credentials):
    normalized = []
    seen_hashes = set()
    for index, credential in enumerate(credentials):
        if not isinstance(credential, dict):
            raise ValueError(f"credential {index} must be an object")
        principal = str(credential.get("principal") or "").strip()
        credential_id = str(
            credential.get("credential_id") or f"credential-{index + 1}"
        ).strip()
        token_hash = str(credential.get("token_sha256") or "").strip().lower()
        roles = credential.get("roles")

        if not PRINCIPAL_PATTERN.fullmatch(principal):
            raise ValueError(f"credential {index} has an invalid principal")
        if not PRINCIPAL_PATTERN.fullmatch(credential_id):
            raise ValueError(f"credential {index} has an invalid credential_id")
        if not SHA256_PATTERN.fullmatch(token_hash):
            raise ValueError(f"credential {index} has an invalid token_sha256")
        if token_hash in seen_hashes:
            raise ValueError("duplicate review API token hash")
        if not isinstance(roles, list) or not roles:
            raise ValueError(f"credential {index} must contain roles")
        normalized_roles = frozenset(str(role).strip().lower() for role in roles)
        unknown_roles = normalized_roles - VALID_ROLES
        if unknown_roles:
            raise ValueError(
                f"credential {index} has unknown roles: {', '.join(sorted(unknown_roles))}"
            )

        seen_hashes.add(token_hash)
        normalized.append(
            {
                "principal": principal,
                "credential_id": credential_id,
                "token_sha256": token_hash,
                "roles": normalized_roles,
            }
        )
    return normalized


def token_sha256(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token():
    token = secrets.token_urlsafe(32)
    return token, token_sha256(token)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a NarrowCTI review API bearer token and SHA-256 hash."
    )
    parser.parse_args(argv)
    token, token_hash = generate_token()
    print(f"token={token}")
    print(f"token_sha256={token_hash}")
    return 0


if __name__ == "__main__":
    main()
