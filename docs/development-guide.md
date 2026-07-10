# Development Guide

This guide explains how contributors can work on NarrowCTI Community Edition
without mixing local lab state, secrets or release evidence into the repository.

## Principles

- Keep changes small and focused.
- Preserve OpenCTI graph hygiene.
- Prefer source-backed evidence over broad inference.
- Add tests for scoring, policy, deduplication, source parsing and graph export
  behavior.
- Update product documentation when operator behavior changes.
- Never commit secrets, `.env` files, local `state/` data, raw feed dumps or
  local agent instructions.

## Branch Flow

```text
feature/* -> dev -> main -> version tag -> GitHub Release
```

Do not develop directly on `main`. Keep pull requests focused on one purpose.

## Local Python Setup

Use Python 3.11 when possible:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r connectors\otx\requirements.txt
```

Run the unit suite:

```powershell
python -m unittest discover -s tests -v
```

## Docker Validation

Build the local gateway image:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml build narrowcti-gateway
```

Run the release validation helper:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate-release.ps1 -Image narrowcti/gateway:local
```

To inspect Docker commands without executing them:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate-release.ps1 -Image narrowcti/gateway:local -Preview
```

The public GitHub CI compiles supported modules and runs:

```text
python -m unittest discover -s tests -v
```

## Source Adapter Work

Use `docs/source-adapter-onboarding-v0.7.md` before adding or changing an
adapter.

Adapter work should document:

- source identity and author naming;
- rate limits and timeouts;
- dry-run behavior;
- state keys;
- source metadata mapping;
- graph candidate extraction;
- deduplication boundaries;
- OpenCTI object and relationship targets;
- tests using sanitized payload samples.

## Graph Export Work

Graph export changes must be conservative. Do not promote an entity or
relationship just because a string exists in a payload.

Every graph export change should define:

- source field and provenance;
- target OpenCTI/STIX object type;
- relationship type;
- confidence and policy behavior;
- deduplication strategy;
- canonical OpenCTI lookup behavior when supported;
- audit evidence and tests.

## Documentation Work

Use `docs/README.md` as the documentation index.

Product docs should help operators install, configure, validate and understand
the gateway. Development evidence may remain versioned for transparency, but
release source archives are curated through `.gitattributes`.

## Pull Request Checklist

Before opening a pull request:

- run tests or explain why they could not be run;
- update docs for operator-visible changes;
- avoid committing local state, secrets or lab payloads;
- include validation evidence for graph export behavior;
- keep release notes curated and operator-facing.
