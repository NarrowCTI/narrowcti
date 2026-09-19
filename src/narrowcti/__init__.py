"""NarrowCTI canonical package namespace."""

from __future__ import annotations

try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("narrowcti")
    except PackageNotFoundError:
        __version__ = "0+unknown"
except ImportError:  # pragma: no cover - importlib.metadata is in supported Python
    __version__ = "0+unknown"


__all__ = ["__version__"]
