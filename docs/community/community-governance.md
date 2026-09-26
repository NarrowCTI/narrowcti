# Community Governance

This is the public governance contract for NarrowCTI Community Edition. It
defines what the community may contribute, who reviews changes, which GitHub
permissions are appropriate and how a reviewed contribution becomes a release.

## Governance Principle

NarrowCTI is open source and community contributions are welcome across the
product. Open source access means that anyone can inspect the code, open an
issue, propose documentation, submit tests or open a pull request. It does not
mean that every contributor receives write access or that a pull request merges
without maintainer review.

The repository owner currently retains final merge and release authority. A
trusted maintainer team may be added later without changing the public review
contract.

## What The Community Can Contribute

| Surface | Examples | Review level |
| --- | --- | --- |
| Public product docs | Configuration, deployment, architecture, API and troubleshooting corrections | Maintainer review and documentation checks. |
| Tests and pure logic | Normalization, scoring fixtures, policy tests and report tests | Maintainer review plus CI. |
| Core and gateway | Decision engine, state, quarantine, reporting and runtime changes | Code Owner review, tests and security impact review. |
| Source adapters | OTX/MISP changes and future governed adapters | Adapter contract, sanitized source evidence, rate-limit/state review and CI. |
| Graph/export mapping | STIX objects, relationships, deduplication and OpenCTI compatibility | Code Owner review, provenance, graph-hygiene and contract or real-feed evidence. |
| Deployment and CI | Compose, Dockerfile, workflows and release automation | Owner or delegated maintainer review; security checks are blocking. |

Community contributors may propose core changes. The project does not reserve
the core for an internal team, but it does reserve merge authority for trusted
maintainers who can evaluate compatibility, security, graph pollution and
release impact.

## Public Product Versus Maintainer Evidence

Public documentation must help an operator or contributor install, configure,
test, understand and safely extend NarrowCTI. It may include architecture,
decision rules, sanitized evidence contracts and release validation summaries.

The following do not belong in the public product path:

- private market positioning or competitive strategy;
- customer or private feed payloads;
- local OpenCTI/MISP state and raw lab evidence;
- credentials, tokens, local paths or `AGENTS.md` instructions;
- unreleased commercial packaging or internal legal strategy.

The public repository cannot erase an already published Git history without a
disruptive history rewrite. Removing a file from the current tree and excluding
it from release archives prevents it from being part of the v1.0 product
surface; it does not claim that historical Git objects never existed.

## GitHub Permission Model

Use the smallest role that matches the duty:

| Actor | Recommended access | Responsibilities |
| --- | --- | --- |
| Public contributor | No repository write access; fork and pull request | Proposal, tests, evidence and response to review. |
| Triage helper | `triage` | Classify issues, request reproduction and apply labels; no code push. |
| Trusted maintainer | `maintain` | Review and merge approved PRs, manage issues and routine repository work. |
| Security or release delegate | `maintain` plus explicitly delegated settings access | Security triage or release preparation only. |
| Repository owner | `admin` | Branch rules, secrets, security settings, releases and maintainer delegation. |

No community contributor receives release credentials, security settings or
direct push access to `main` by default. `CODEOWNERS` currently names the
repository owner as the default reviewer and can be expanded when a trusted
maintainer team exists.

## Pull Request Review Flow

```text
issue or discussion
  -> fork or feature branch
  -> focused pull request
  -> automated CI and security checks
  -> Code Owner review
  -> requested changes and revalidation
  -> merge to dev or main according to scope
  -> release only from main
```

Every code-modifying PR must have at least one approving maintainer or Code
Owner review and all applicable required checks green. Approvals become stale
after new code is pushed. The reviewer evaluates:

1. scope and backward compatibility;
2. source evidence, provenance and error behavior;
3. scoring, TLP, quarantine, deduplication and graph-hygiene effects;
4. tests and reproducible validation commands;
5. public documentation and release-archive classification;
6. secrets, dependency, workflow and container impact.

The person who opens a PR does not self-approve it. A maintainer may request a
second review for security, release or graph-export changes.

## Required Repository Settings

These settings are GitHub controls and cannot be expressed completely in a
tracked Markdown file. Before the v1.0 release, the owner should configure:

### `main`

- require a pull request before merging;
- require at least one approval;
- require review from Code Owners;
- dismiss stale approvals after new commits;
- require the branch to be up to date before merging;
- require these job checks when the changed surface makes them applicable:
  `Python tests`, `Python quality, SAST and dependencies`, `Build, scan and
  publish gateway image` and `Analyst review API OWASP ZAP`;
- block force pushes and branch deletion;
- restrict direct pushes to the owner or explicitly trusted maintainers;
- keep emergency bypass restricted to the owner and record every bypass.

### `dev`

- require a pull request and one maintainer approval;
- require `CI` and `Security and Quality`;
- block force pushes;
- permit only the owner or trusted maintainers to merge integration work.

### Security and automation

- enable private vulnerability reporting;
- enable Dependabot alerts and security updates;
- keep secret scanning and push protection enabled when available;
- keep GitHub Actions default permissions at read-only and elevate a job only
  for the exact artifact operation it needs;
- pin third-party Actions to reviewed full commit SHAs and update them through
  Dependabot or an explicit maintainer review;
- review fork pull request workflow permissions before allowing privileged jobs;
- keep release and registry credentials unavailable to untrusted pull requests;
- protect the `release` environment with maintainer approval and restrict it to
  `main` and semantic version tags.

Branch protection is a repository setting, not a substitute for `CODEOWNERS`.
`CODEOWNERS` identifies the reviewer; the branch rule is what enforces review.

## Release Authority

Contributors do not create stable tags or publish the Community image. The
owner or delegated release maintainer validates the release checklist, merges to
`main`, creates the immutable tag, publishes the GitHub Release and confirms the
image/SBOM evidence. Release provenance is documented in
`release-process.md`.

## OpenCTI Comparison

OpenCTI demonstrates two complementary contribution surfaces: its main public
repository accepts platform contributions, while the public connectors
repository governs connector-specific templates, technical requirements, STIX
quality and verified-connector review. NarrowCTI follows the same principle in
one repository: core, gateway, exporters and documentation are open to PRs, and
adapter changes receive additional source-contract and integration scrutiny.

The model is therefore contribution to both local parts and the global product,
with stronger gates for changes that can affect the entire graph or release.
