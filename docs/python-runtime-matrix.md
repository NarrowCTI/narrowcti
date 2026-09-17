# Python runtime matrix

This matrix is the W1/PR-02 runtime contract for the Community package.

| Surface | Certified value | Source of truth |
| --- | --- | --- |
| Compatibility floor | Python `>=3.11` | `pyproject.toml` |
| Certified CI/release runtime | Python `3.11` only | `.github/workflows/ci.yml`, `.github/workflows/security-quality.yml` |
| Ruff target | `py311` | `pyproject.toml` |
| Release container | `python:3.11-slim` | `Dockerfile.gateway` |
| Contributor setup | Python `3.11` | `docs/development-guide.md` |

Python 3.14 remains a documented local laboratory environment only. Versions
newer than 3.11 may be installable because the compatibility floor is `>=3.11`,
but they are not part of the currently certified CI/release matrix. A
multi-Python support matrix requires a separately approved change and is outside
this PR.

The current top-level package layout remains intentionally unchanged. Package
discovery is restricted to `connectors*`, `core*`, `exporters*` and `gateway*`;
the `src/` migration is reserved for PR-03.
