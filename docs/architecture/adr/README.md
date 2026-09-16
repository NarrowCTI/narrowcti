# Architecture decision records

This directory is the W0 index and skeleton for the Community 2.0 migration.
It is documentation-only: no target architecture or runtime behavior is
implemented by PR-01.

| ADR | Topic | W0 status |
| --- | --- | --- |
| ADR-001 | Community migration principles | skeleton |
| ADR-002 | Source-tree/package boundary | skeleton |
| ADR-003 | Configuration ownership and typed boundary | skeleton |
| ADR-004 | Source adapter ports | skeleton |
| ADR-005 | Domain primitives | skeleton |
| ADR-006 | Graph evidence contract | skeleton |
| ADR-007 | Candidate and promotion policy | skeleton |
| ADR-008 | OpenCTI canonical lookup | skeleton |
| ADR-009 | STIX/export boundary | skeleton |
| ADR-010 | Decision and audit record | skeleton |
| ADR-011 | Quarantine/review boundary | skeleton |
| ADR-012 | Observability and operational evidence | skeleton |
| ADR-013 | Community/Enterprise separation | skeleton |
| ADR-014 | Compatibility and rollout policy | skeleton |

Each ADR must be reviewed and approved before the migration wave that depends
on it. W0 records the decision surfaces only; it does not create compatibility
shims, new ports, domain packages or migration code.

Use [`template.md`](template.md) for future ADR content.
