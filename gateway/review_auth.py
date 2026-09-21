"""Historical compatibility wrapper for review authentication."""

from narrowcti.api.review.auth import (
    PRINCIPAL_PATTERN,
    ROLE_PERMISSIONS,
    SHA256_PATTERN,
    VALID_ROLES,
    ReviewCredentialStore,
    ReviewPrincipal,
    generate_token,
    main,
    normalize_credentials,
    token_sha256,
)

__all__ = [
    "PRINCIPAL_PATTERN", "ROLE_PERMISSIONS", "SHA256_PATTERN", "VALID_ROLES",
    "ReviewCredentialStore", "ReviewPrincipal", "generate_token", "main",
    "normalize_credentials", "token_sha256",
]


if __name__ == "__main__":
    main()
