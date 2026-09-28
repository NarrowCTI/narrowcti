"""Canonical Community Web and bearer API role entrypoint."""

from __future__ import annotations

from narrowcti.api.web.app import create_web_app
from narrowcti.infrastructure.config.web_settings import load_web_settings


def main():
    settings = load_web_settings()
    import uvicorn

    uvicorn.run(
        create_web_app(settings=settings),
        host=settings.host,
        port=settings.port,
        access_log=True,
        proxy_headers=False,
        server_header=False,
        date_header=False,
    )


__all__ = ["create_web_app", "load_web_settings", "main"]


if __name__ == "__main__":
    main()
