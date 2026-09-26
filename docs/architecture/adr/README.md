# Architecture decision records

This directory is the migration decision index for Community 2.0. W0 created
the decision records; the records marked accepted authorize only the bounded
wave and PR scopes stated in those records.

| ADR | Topic | W0 status |
| --- | --- | --- |
| [MIG-ADR-001](MIG-ADR-001.md) | Community migration principles | accepted |
| [MIG-ADR-002](MIG-ADR-002.md) | Source-tree/package boundary | accepted for PR-02, PR-03 and PR-05 compatibility addendum |
| [MIG-ADR-003](MIG-ADR-003.md) | Configuration ownership and typed boundary | accepted |
| [MIG-ADR-004](MIG-ADR-004.md) | Source adapter ports | proposed |
| [MIG-ADR-005](MIG-ADR-005.md) | Domain primitives | accepted for PR-05 |
| [MIG-ADR-006](MIG-ADR-006.md) | Graph evidence boundary | accepted for W4 / PR-12 |
| [MIG-ADR-007](MIG-ADR-007.md) | Candidate and promotion policy | proposed |
| [MIG-ADR-008](MIG-ADR-008.md) | OpenCTI graph provider boundary | accepted for W4 / PR-13 |
| [MIG-ADR-009](MIG-ADR-009.md) | STIX/IR/compiler and OpenCTI export boundary | accepted for W4 / PR-14 |
| [MIG-ADR-010](MIG-ADR-010.md) | Decision and audit record | proposed |
| [MIG-ADR-011](MIG-ADR-011.md) | Quarantine/review boundary | accepted for PR-07 |
| [MIG-ADR-012](MIG-ADR-012.md) | Observability and operational evidence | accepted for W5 / PR-17 |
| [MIG-ADR-013](MIG-ADR-013.md) | Community/Enterprise separation | proposed |
| [MIG-ADR-014](MIG-ADR-014.md) | Compatibility and rollout policy | accepted |
| [MIG-ADR-015](MIG-ADR-015.md) | Community repository ports and local persistence | accepted for PR-06 |
| [MIG-ADR-016](MIG-ADR-016.md) | Ingestion application orchestration boundary | accepted for PR-08 |
| [MIG-ADR-017](MIG-ADR-017.md) | MISP source extraction boundary | accepted for PR-09 |
| [MIG-ADR-018](MIG-ADR-018.md) | Gateway runtime and source provider registry boundary | accepted for W5 / PR-15 |
| [MIG-ADR-019](MIG-ADR-019.md) | Capability registry and entitlement provider boundary | accepted for W6 / PR-18 |
| [MIG-ADR-021](MIG-ADR-021.md) | Detection foundation domain contracts | accepted for W6 / PR-19 |
| [MIG-ADR-022](MIG-ADR-022.md) | Package-based runtime and deployment portability | accepted for W7 / PR-20 |

MIG-ADR-020 is intentionally reserved for the Shared Web Architecture /
Community Basic UI / Source Explorer / Web Security decision defined by the
v0.5 migration plan.

Each ADR must be reviewed and approved before the migration wave that depends
on it. Accepted records remain bounded by their stated PR scope. PR-03 adds
only the deterministic `src/narrowcti` compatibility bootstrap described in
MIG-ADR-002; it does not create ports, domain packages or functional module
moves.

Use [`template.md`](template.md) for future ADR content.
