# Community Issue Triage

This document defines the initial public issue and label model for NarrowCTI
Community Edition.

The labels can be created manually in GitHub now and automated later.

## Type Labels

- `type:bug`: documented behavior is broken.
- `type:feature`: new capability or enhancement request.
- `type:docs`: documentation improvement.
- `type:security`: security hardening without public vulnerability details.
- `type:question`: support or usage question.
- `type:maintenance`: CI, dependency, repository or release maintenance.

## Component Labels

- `component:gateway`
- `component:core`
- `component:connectors`
- `component:exporters`
- `component:opencti`
- `component:misp`
- `component:otx`
- `component:deployment`
- `component:docs`
- `component:tests`
- `component:ci`

## Area Labels

- `area:scoring`
- `area:deduplication`
- `area:quarantine`
- `area:graph-export`
- `area:graph-lookup`
- `area:stix`
- `area:mitre`
- `area:infrastructure-correlation`
- `area:reporting`
- `area:support-diagnostics`
- `area:release`

## Priority Labels

- `priority:critical`: data loss, unsafe graph pollution, security exposure or
  release blocker.
- `priority:high`: important user-visible behavior or validation blocker.
- `priority:medium`: normal backlog item.
- `priority:low`: cleanup, polish or nice-to-have improvement.

## Contributor Labels

- `good first issue`: small, well-scoped, low-risk issue with clear acceptance
  criteria.
- `help wanted`: useful community contribution, may require project context.
- `needs reproduction`: bug report needs a minimal sanitized reproduction.
- `needs evidence`: source payload, OpenCTI behavior or validation evidence is
  missing.
- `blocked`: cannot proceed without external input or dependency.

## Good First Issue Criteria

An issue can be marked `good first issue` when it:

- does not require secrets, private feed data or live OpenCTI access;
- has clear expected behavior;
- has a narrow file scope;
- can be validated with unit tests or documentation review;
- does not change graph export policy, deduplication semantics or release
  process without maintainer review.

Good examples:

- clarify a configuration variable in docs;
- add a missing unit test for a pure normalization helper;
- improve an issue template;
- fix a typo in public documentation;
- add a sanitized example to a guide.

Avoid `good first issue` for:

- real ingestion behavior changes;
- OpenCTI graph promotion changes;
- source adapter trust or scoring changes;
- security-sensitive fixes;
- release automation.

## Triage Flow

1. Confirm the issue does not contain secrets or private payloads.
2. Apply one type label.
3. Apply one or more component labels.
4. Apply area labels when useful.
5. Apply priority only after impact is understood.
6. Ask for reproduction or evidence when source behavior is unclear.
7. Convert safe, small and documented tasks into `good first issue`.
