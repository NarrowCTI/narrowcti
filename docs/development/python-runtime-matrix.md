# Python runtime matrix

This matrix is the W1/PR-02 runtime contract for the Community package.

| Surface | Certified value | Source of truth |
| --- | --- | --- |
| Compatibility floor | Python `>=3.11` | `pyproject.toml` |
| Certified CI/release runtime | Python `3.11` only | `.github/workflows/ci.yml`, `.github/workflows/security-quality.yml` |
| Ruff target | `py311` | `pyproject.toml` |
| Release container | `python:3.11-slim` | `Dockerfile.gateway` |
| Contributor setup | Python `3.11` | `docs/development/development-guide.md` |

Python 3.14 remains a documented local laboratory environment only. Versions
newer than 3.11 may be installable because the compatibility floor is `>=3.11`,
but they are not part of the currently certified CI/release matrix. A
multi-Python support matrix requires a separately approved change and is outside
this PR.

PR-03 adds the `src/narrowcti` canonical namespace as a compatibility bootstrap
while retaining the top-level implementation packages. Package discovery is
explicitly restricted to `narrowcti*`, `connectors*`, `core*`, `exporters*` and
`gateway*`. Functional module moves remain reserved for later migration PRs.
