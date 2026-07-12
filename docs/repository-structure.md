# Repository Structure

This document explains how the NarrowCTI Community Edition repository is
organized and what belongs in public releases.

## Public Repository Surface

Root-level community and release files:

- `README.md`: project overview, current version and operator starting points.
- `CHANGELOG.md`: public release history summary.
- `VERSION`: current project version.
- `LICENSE`: Apache-2.0 license for the open source core.
- `THIRD_PARTY_NOTICES.md`: dependency and platform notice tracking.
- `CONTRIBUTING.md`: contributor workflow and pull request expectations.
- `SUPPORT.md`: community support and safe issue guidance.
- `SECURITY.md`: vulnerability reporting and sensitive data handling.
- `CODE_OF_CONDUCT.md`: community behavior expectations.

GitHub collaboration files live under `.github/`:

- `CODEOWNERS` for default review responsibility;
- `dependabot.yml` for dependency and action update proposals;
- issue templates for bugs, features, documentation and questions;
- pull request template;
- continuous integration, security and DAST workflows;
- container image publication workflow.

The public contribution and permission model is defined in
`docs/community-governance.md`. GitHub branch protection, private reporting,
secret scanning and repository roles are settings outside the Git tree and must
be checked by the repository owner before release.

## Source Layout

- `config/`: sample and shared configuration files.
- `connectors/`: source adapters such as OTX and MISP.
- `core/`: scoring, policy, graph evidence, deduplication, quarantine and state
  primitives.
- `exporters/`: STIX and OpenCTI export logic.
- `gateway/`: unified gateway runtime, preflight, reporting and operator CLIs.
- `deployment/`: deployment templates and compose-facing material.
- `docs/assets/`: public README and documentation assets such as the project
  logo.
- `scripts/`: validation and maintenance helpers.
- `tests/`: unit and behavior tests.

## Documentation Layout

The documentation index is `docs/README.md`.

Product documentation should explain how to install, configure, operate,
validate and understand NarrowCTI as a CTI gateway. Product docs are safe to
ship in GitHub release source archives.

Development evidence can remain versioned when it helps maintainers understand
validation, source mapping or architecture decisions. Evidence-heavy docs must
not become the first operator surface, and files marked with `export-ignore` are
excluded from release source archives.

## Local Runtime State

`state/` is a local runtime directory. It may contain deduplication state,
quarantine records, audit logs, cache files and local validation evidence.

Only `state/.gitkeep` is allowed in Git. Runtime state is excluded by:

- `.gitignore`;
- `.dockerignore`;
- `.gitattributes` release archive rules.

## Local Agent Instructions

`AGENTS.md` and `agents.md` are local assistant/operator instruction files.
They are not product documentation and must not be published through Git,
Docker build context or release source archives.

They are excluded by:

- `.gitignore`;
- `.dockerignore`;
- `.gitattributes`.

## Release Archive Policy

GitHub automatically exposes source archives for tags and releases. NarrowCTI
uses `.gitattributes` and `export-ignore` to keep those archives focused on:

- source code;
- tests;
- deployment templates;
- public product documentation;
- community contribution and security files.

Release archives must exclude:

- `.env` files and secrets;
- `AGENTS.md` or local agent instructions;
- local runtime `state/`;
- raw feed dumps and private payloads;
- development validation notes marked with `export-ignore`.

Before publishing a release, run the archive inspection described in
`docs/release-process.md`.
