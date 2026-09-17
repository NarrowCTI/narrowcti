# Python runtime matrix

This matrix is the W1/PR-02 runtime contract for the Community package.

| Surface | Certified value | Source of truth |
| --- | --- | --- |
| Package metadata | Python `>=3.11` | `pyproject.toml` |
| CI tests | Python `3.11` | `.github/workflows/ci.yml` |
| CI security and quality | Python `3.11` | `.github/workflows/security-quality.yml` |
| Ruff target | `py311` | `pyproject.toml` |
| Release container | `python:3.11-slim` | `Dockerfile.gateway` |
| Contributor setup | Python `3.11` | `docs/development-guide.md` |

Python 3.14 remains a documented local laboratory environment only. It is not
part of the certified CI or release support contract in PR-02. A multi-Python
support matrix requires a separately approved change and is outside this PR.

The current top-level package layout remains intentionally unchanged. Package
discovery is restricted to `connectors*`, `core*`, `exporters*` and `gateway*`;
the `src/` migration is reserved for PR-03.
