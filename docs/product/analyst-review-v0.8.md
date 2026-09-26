# Analyst Review - v0.8.0

## Purpose

This document defines the v0.8 analyst review foundation for quarantine,
release, rejection, partial release, audit and future policy tuning workflows.

The product direction is:

```text
quarantine evidence
  -> analyst review service
  -> CLI/API/UI consumers
  -> release, reject, partial release or export
  -> audit evidence
```

## Current Implementation

v0.8 introduces `gateway.review.AnalystReviewService` as the internal review
API. The existing `gateway.quarantine` CLI now delegates to that service rather
than calling the repository directly for review operations.

This is not an HTTP API yet. It is the product-safe service boundary that a
future API server or UI can reuse without duplicating quarantine transition
logic.

Implemented service capabilities:

- List quarantine records by status and source.
- Retrieve one quarantine record by id.
- Summarize queue state by status and source.
- Release a pending record.
- Release selected indicator types from a pending record.
- Reject a pending record.
- Export released records through the existing dry-run-by-default export path.
- Read release/reject/export audit events by id, action and limit.

## CLI Surface

The CLI remains the operator-facing interface in v0.8:

```powershell
python -m gateway.quarantine --repository state\quarantine.jsonl summary
python -m gateway.quarantine --repository state\quarantine.jsonl list --status pending
python -m gateway.quarantine --repository state\quarantine.jsonl show --id <quarantine-id>
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release --id <quarantine-id> --reason "Relevant to monitored scope"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl release-indicators --id <quarantine-id> --type domain,url --reason "High-value observables"
python -m gateway.quarantine --repository state\quarantine.jsonl --release-audit-file state\audit\releases.jsonl reject --id <quarantine-id> --reason "Out of scope"
python -m gateway.quarantine --repository state\quarantine.jsonl export-released --id <quarantine-id>
python -m gateway.quarantine --release-audit-file state\audit\releases.jsonl audit --limit 20
```

`export-released` remains dry-run by default. Use `--execute` only after the
record was reviewed, OpenCTI capacity is acceptable and deduplication posture is
validated.

## Review Governance

Review actions must remain explainable:

- `NARROWCTI_RELEASE_QUARANTINE_REQUIRES_REASON=true` should remain the default
  for governed environments.
- `NARROWCTI_REVIEWER` should identify the operator or automation principal
  performing the action.
- Release, rejection and export actions write release audit evidence when
  `NARROWCTI_RELEASE_AUDIT_FILE` is configured.
- Partial release should be used when only selected observables are relevant to
  the monitored scope.

## Future API/UI Boundary

A future HTTP API or UI should call `AnalystReviewService` instead of
reimplementing repository transitions. That preserves:

- One transition policy for CLI, API and UI.
- One audit event model.
- One export replay path.
- One place to add future policy tuning and authorization checks.

Expected future UI/API capabilities:

- Queue dashboard with status/source counts.
- Record detail view with source evidence, indicators, score and graph metadata.
- Release/reject forms with mandatory reason support.
- Partial release selector by indicator type.
- Audit timeline per quarantine record.
- Export preview and export execution controls.
- Policy tuning recommendations based on repeated release/reject patterns.

## Non-Goals In v0.8

- HTTP server.
- Browser UI.
- Role-based access control.
- Runtime policy tuning writeback.
- Automatic release from quarantine without analyst or explicit automation
  action.
