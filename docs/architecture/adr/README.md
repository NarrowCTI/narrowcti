# Architecture decision records

This directory is the W0 index and skeleton for the Community 2.0 migration.
It is documentation-only: no target architecture or runtime behavior is
implemented by PR-01.

| ADR | Topic | W0 status |
| --- | --- | --- |
| [MIG-ADR-001](MIG-ADR-001.md) | Community migration principles | proposed |
| [MIG-ADR-002](MIG-ADR-002.md) | Source-tree/package boundary | proposed |
| [MIG-ADR-003](MIG-ADR-003.md) | Configuration ownership and typed boundary | proposed |
| [MIG-ADR-004](MIG-ADR-004.md) | Source adapter ports | proposed |
| [MIG-ADR-005](MIG-ADR-005.md) | Domain primitives | proposed |
| [MIG-ADR-006](MIG-ADR-006.md) | Graph evidence contract | proposed |
| [MIG-ADR-007](MIG-ADR-007.md) | Candidate and promotion policy | proposed |
| [MIG-ADR-008](MIG-ADR-008.md) | OpenCTI canonical lookup | proposed |
| [MIG-ADR-009](MIG-ADR-009.md) | STIX/export boundary | proposed |
| [MIG-ADR-010](MIG-ADR-010.md) | Decision and audit record | proposed |
| [MIG-ADR-011](MIG-ADR-011.md) | Quarantine/review boundary | proposed |
| [MIG-ADR-012](MIG-ADR-012.md) | Observability and operational evidence | proposed |
| [MIG-ADR-013](MIG-ADR-013.md) | Community/Enterprise separation | proposed |
| [MIG-ADR-014](MIG-ADR-014.md) | Compatibility and rollout policy | proposed |

Each ADR must be reviewed and approved before the migration wave that depends
on it. W0 records the decision surfaces only; it does not create compatibility
shims, new ports, domain packages or migration code.

Use [`template.md`](template.md) for future ADR content.
