"""Canonical Web/API role entrypoint without UI implementation."""

from __future__ import annotations

from narrowcti.api.review.app import create_app, load_review_api_settings


def main():
    settings = load_review_api_settings()
    import uvicorn

    uvicorn.run(
        create_app(settings=settings),
        host=settings.host,
        port=settings.port,
        access_log=True,
        server_header=False,
        date_header=False,
    )


__all__ = ["create_app", "load_review_api_settings", "main"]


if __name__ == "__main__":
    main()
