# MIG-ADR-011 — Quarantine and review boundary

- Status: accepted
- Context: Low-confidence candidates can be held in a persistent quarantine repository and released by review. The current Community implementation combines the quarantine record, transition rules and a local append-only JSONL repository in `core.quarantine`.
- Proposed Decision: Define quarantine state and release/reject/partial-release/exported-state transitions as pure domain semantics. Keep the historical `QuarantineRepository` concrete name as a local adapter and introduce a minimal `QuarantineStore` port for current consumers. Release approval remains separate from export, review reasons remain enforceable on direct repository calls, and every transition remains auditable and idempotent.
- Temporal Semantics: Canonical quarantine code uses a stdlib UTC formatter without microseconds. Transition functions receive `recorded_at` explicitly; the local adapter obtains the timestamp and supplies it. No clock port or additional time abstraction is introduced.
- Partial Release Semantics: Indicator types preserve the current quarantine contract exactly: CSV/iterable values are stripped and lowercased, and indicator lookup checks `type`, then `indicator_type`, then `observable_type`, followed by strip/lowercase. No aliases from `domain.intelligence.indicator_types` are applied.
- Persistence Boundary: JSONL replay, append operations and release-audit serialization remain local-adapter responsibilities. The compatibility module `core.quarantine` reexports canonical domain symbols and the canonical concrete repository while retaining `bounded_raw_snapshot` and any required legacy surface.
- Export Boundary: A released record is not automatically exported. Dry-run, export errors and the all-known-indicators deduplication path preserve their existing side-effect contracts. In the deduplication path, no OpenCTI export and no artifact mark occur; `mark_exported(count=0, duplicate_count=N)` records the `dedup-skip` result.
- Alternatives: Drop low scores irreversibly; export first and review later; replace the historical concrete repository name with a new adapter-specific class; normalize quarantine indicator aliases with the intelligence domain.
- Consequences: Analysts can release, partially release or reject with evidence and without bypassing policy. Existing processors, Review API, CLI and exporter remain compatible while the domain/port/adapter boundary becomes explicit.
- Dependencies: Existing quarantine/review/export characterization, MIG-ADR-002, MIG-ADR-014 and MIG-ADR-015.
- Related ADRs: MIG-ADR-007 and MIG-ADR-010.
- Target Wave: W2 quarantine domain/repository boundary, with existing W5 review/API consumers preserved during compatibility.

## PR-16 addendum — review service, API and persistence separation

- Scope: W5 / PR-16 only. This addendum separates review application behavior,
  API/authentication boundaries, CLI composition and local audit reading without
  changing the quarantine domain, `QuarantineStore` port or local quarantine
  repository contract.
- Decision: canonical review code is owned by
  `narrowcti.application.review`, `narrowcti.api.review`,
  `narrowcti.cli.quarantine` and
  `narrowcti.adapters.persistence.local.review_audit`. The application service
  receives an injected export operation; API and CLI composition provide the
  canonical OpenCTI exporter only for real execution. Dry-run remains usable
  without an exporter callable.
- Compatibility: the historical `gateway.review`,
  `gateway.quarantine_export`, `gateway.review_api`,
  `gateway.review_auth` and `gateway.quarantine` modules remain importable.
  Their compatibility wrappers preserve constructor signatures, `from_paths`,
  CLI output/argparse behavior, API status behavior and the historical default
  OpenCTI exporter. No identity guarantee is introduced where adaptive
  injection is required; pure authentication symbols and `ReviewSummary` keep
  identity with their canonical owners where practical.
- Audit: JSONL audit reading is a local adapter concern. Missing/empty files
  return an empty list, UTF-8 BOM is accepted, event order is preserved and
  JSON decoding errors retain their existing behavior. The application layer
  receives audit events and only filters them; it does not discover paths or
  perform filesystem I/O.
- Side-effect order: successful real export remains export, artifact mark,
  quarantine mark-exported and audit append in the existing order. Dry-run,
  non-exportable, already-exported, empty-release, dedup-skip and export-error
  branches retain their existing mutations and results.
- Dependencies: MIG-ADR-011 remains the governing quarantine/review boundary;
  this addendum does not make a new application port, OpenCTI exporter port or
  DecisionRecord migration, and does not alter the `QuarantineStore` contract.
- Deferred: DecisionRecord extraction, processor cutover, OpenCTI mutation
  migration and broader application orchestration remain outside PR-16.
