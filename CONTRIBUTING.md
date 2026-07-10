# Contributing to NarrowCTI

Thank you for considering a contribution to NarrowCTI.

NarrowCTI is an OpenCTI-native threat intelligence gateway. Its goal is to turn
raw intelligence feeds into curated, explainable and auditable graph-ready
intelligence before OpenCTI ingestion.

## Ways to Contribute

- Report bugs with reproducible evidence.
- Propose source adapters, enrichment logic or graph mapping improvements.
- Improve documentation, deployment examples and operational runbooks.
- Add tests for source payloads, scoring policy, deduplication and OpenCTI graph
  export behavior.
- Help triage issues and validate real-world feed behavior.

Good first contribution areas are documentation corrections, reproducible bug
reports, small tests for existing behavior, bounded source payload fixtures with
sensitive values removed, and improvements to operator runbooks.

## Project Principles

- Preserve OpenCTI graph hygiene. Do not create duplicate or weakly supported
  graph entities.
- Prefer source-backed evidence over broad inference.
- Keep curations explainable through score details, policy decisions and audit
  metadata.
- Keep secrets, local state, feed payload dumps and lab evidence out of commits.
- Use small, focused changes with tests that match the risk of the change.
- Treat image publishing, release notes and migration guidance as product
  surfaces, not internal chores.

## Issue Triage

Use the GitHub issue templates whenever possible.

- Bugs should include version, deployment mode, enabled sources, expected
  behavior, actual behavior and sanitized logs or audit snippets.
- Feature requests should explain the analyst/operator outcome, affected
  OpenCTI areas and whether the feature changes ingestion, scoring,
  deduplication, quarantine, graph export or reporting.
- Security reports must follow `SECURITY.md` and should not be opened as public
  issues with exploit details.

Maintainers should prefer clear labels such as `bug`, `docs`, `feature`,
`good first issue`, `source-adapter`, `graph-export`, `security`,
`deployment`, `needs-evidence` and `blocked`.

## Branching Model

NarrowCTI uses controlled feature branches:

```text
feature/* -> dev -> main -> version tag / GitHub release
```

- Do not develop directly on `main`.
- Keep `main` stable and releasable.
- Use descriptive branch names, for example `feature/misp-graph-export` or
  `fix/opencti-lookup-timeout`.
- Keep pull requests focused on one purpose.

## Development Setup

The full contributor guide is tracked in `docs/development-guide.md`.

Install the Python dependencies used by the gateway image:

```text
python -m pip install -r connectors/otx/requirements.txt
```

Run the test suite:

```text
python -m unittest discover -s tests -v
```

Run the product validation script when Docker is available:

```text
powershell -ExecutionPolicy Bypass -File scripts\validate-v0.6.ps1 -Image narrowcti/gateway:local
```

## Pull Requests

Before opening a pull request:

- Confirm no `.env`, state files, feed dumps, tokens or local agent instructions
  are included.
- Add or update tests for behavior changes.
- Update product documentation when configuration, deployment or operator
  behavior changes.
- Keep development evidence out of user-facing release notes.

Recommended PR title format:

```text
[component] Short description (#issue)
```

Examples:

```text
[gateway] Add OpenCTI relationship audit evidence (#42)
[docs] Clarify MISP source adapter configuration (#43)
```

Common components are `gateway`, `core`, `connectors`, `exporters`, `docs`,
`deployment`, `tests` and `ci`.

## Release and Image Contributions

Changes that affect the Docker image, deployment template, public configuration
surface or release packaging should also update:

- `docs/container-images.md`;
- `docs/deployment-operations.md`;
- `docs/configuration-reference.md`;
- `docs/release-process.md`;
- `.github/workflows/container-image.yml`, when image publishing changes.

Container image tags are part of the public contract. Do not change tag naming
or move `latest` semantics without documenting the migration.

## Security Reports

Do not disclose vulnerabilities publicly before maintainers have had time to
review and fix them. See `SECURITY.md`.
