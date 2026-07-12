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

## Contribution Scope And Ownership

Community contributors may propose changes across the repository, including the
gateway runtime, `core/` decision and graph logic, OTX/MISP adapters, exporters,
tests, deployment templates and public documentation. A contributor does not
need write access to submit a pull request.

The repository owner and designated maintainers retain merge authority. A pull
request is a proposal until a maintainer has reviewed the design, source
evidence, security impact, tests and documentation. Contributors must not be
given direct push access to `main` or `dev` merely because they opened a useful
pull request.

The review bar is proportional to impact:

| Change area | Required review focus |
| --- | --- |
| Documentation, tests and pure helpers | Scope, accuracy, tests and public-data hygiene. |
| Source adapters and parsing | Sanitized payload shape, retries, limits, state, provenance and failure behavior. |
| Scoring, TLP, quarantine and deduplication | Decision effects, false-negative risk, replay behavior and audit evidence. |
| STIX/OpenCTI graph export | Object/relationship mapping, canonical lookup, graph hygiene, real or contract evidence and rollback. |
| CI, image, release or security policy | Supply-chain impact, permissions, artifact handling and maintainer approval. |

The project may later add trusted maintainers or a maintainer team without
changing this process. Permission should be granted through the smallest GitHub
repository role needed for the duty; review authority and repository
administration are separate responsibilities.

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

Maintainers should prefer the documented taxonomy: `type:bug`, `type:docs`,
`type:feature`, `type:security`, `type:question`, component labels such as
`component:core` or `component:misp`, area labels such as `area:graph-export`,
and workflow labels such as `good first issue`, `needs reproduction`,
`needs evidence` and `blocked`.

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

GitHub branch rules must require pull requests, passing required workflows and a
maintainer or Code Owner approval before changes reach `main`. `dev` should also
reject direct pushes once the community workflow is active. Emergency bypasses
are restricted to the owner, must be recorded in the issue or release evidence,
and must not be used to skip a security fix review.

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
powershell -ExecutionPolicy Bypass -File scripts\validate-release.ps1 -Image narrowcti/gateway:local
```

## Pull Requests

Before opening a pull request:

- Confirm no `.env`, state files, feed dumps, tokens or local agent instructions
  are included.
- Add or update tests for behavior changes.
- Update product documentation when configuration, deployment or operator
  behavior changes.
- Keep development evidence out of user-facing release notes.
- Identify whether the change belongs to public product documentation or local
  maintainer evidence. Do not add market strategy, private lab evidence or
  competitive research to the public operator path.

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

## Maintainer Review Flow

1. Contributor opens or references an issue and submits a focused pull request.
2. Automated CI, quality, security and image checks run on the proposed commit.
3. A maintainer checks scope, provenance, graph impact, tests, documentation,
   secrets and release-archive impact.
4. Requested changes are resolved and stale approvals are dismissed after code
   changes.
5. The maintainer merges only after required checks and review are green.
6. Release work is performed from `main` through the documented tag and GitHub
   Release process; contributor PRs do not publish releases directly.
