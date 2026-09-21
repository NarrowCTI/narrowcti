"""Historical compatibility wrapper for the canonical review API."""

from narrowcti.api.review.app import (
    DecisionRequest,
    PartialReleaseRequest,
    ReviewApiSettings,
    build_export_dedup,
    create_app,
    default_opencti_client_factory,
    env_bool,
    load_review_api_settings,
    main,
)

__all__ = [
    "ReviewApiSettings", "DecisionRequest", "PartialReleaseRequest", "env_bool",
    "load_review_api_settings", "default_opencti_client_factory",
    "build_export_dedup", "create_app", "main",
]


if __name__ == "__main__":
    main()
