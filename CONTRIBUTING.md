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

## Project Principles

- Preserve OpenCTI graph hygiene. Do not create duplicate or weakly supported
  graph entities.
- Prefer source-backed evidence over broad inference.
- Keep curations explainable through score details, policy decisions and audit
  metadata.
- Keep secrets, local state, feed payload dumps and lab evidence out of commits.
- Use small, focused changes with tests that match the risk of the change.

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

## Security Reports

Do not disclose vulnerabilities publicly before maintainers have had time to
review and fix them. See `SECURITY.md`.
