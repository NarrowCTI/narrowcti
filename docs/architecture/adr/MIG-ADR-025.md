# MIG-ADR-025 — Community runtime role foundation

- Status: accepted and implemented in Community
- Date: 2026-09-27
- Scope: Community runtime roles and process-safe coordination
- Related decisions: MIG-ADR-002, MIG-ADR-003, MIG-ADR-014, MIG-ADR-015, MIG-ADR-018, MIG-ADR-019, MIG-ADR-020, MIG-ADR-022, MIG-ADR-024

## Context

Community provides Web/API, Worker and one-shot Ops roles from the same
package and container image. The roles share runtime coordination, while
source checkpoints, quarantine, release audit, artifact/graph indexes,
decision audit and summaries retain their existing JSON/JSONL formats.
Those business-state files do not provide transactional cross-process job
claims, leases or mutation coordination.

## Decision

Community has explicit Web/API, Worker and Ops roles. One active Worker may
hold the lease for a runtime-state scope. The Worker owns source ingestion and
the process-safe Worker lease; the legacy `gateway.connector` entrypoint
delegates to the canonical Worker lifecycle.

Application code consumes role, job and coordination contracts through
inward-facing ports. The `JobRepository` supports idempotent submission,
atomic pending-to-running claims and owner/attempt-fenced completion or
failure. Worker lease and mutation-coordination contracts are implemented by
the local SQLite runtime-store adapter.

SQLite stores jobs, leases, coordination metadata and schema metadata only.
Business state remains in its existing JSON/JSONL files and retains its
schemas. The runtime database is supported on a local filesystem or validated
Docker volume; arbitrary NFS/SMB locking semantics are not declared supported.
Unsupported runtime database schema versions fail closed rather than being
overwritten.

The Worker separates source-ingestion cadence from bounded-job polling.
Worker, active-job and mutation-coordination leases use bounded heartbeats;
expired leases can be reclaimed after process failure. Quarantine/release
mutations are serialized across processes while retaining their synchronous
API behavior. Real artifact export and artifact marking have one Worker
mutation owner; the Review API remains a synchronous bounded command facade.
Web receives review/runtime configuration and its own credential file, while
source credentials remain Worker-owned. Ops real-export commands submit the
same bounded job contract rather than bypassing Worker ownership.

## Rationale

- JSON/JSONL business files do not provide atomic claims or owner-fenced
  completion across processes.
- SQLite provides transactional claims, uniqueness, lease ownership and crash
  recovery using the Python standard library for the supported local/runtime
  volume topology.
- Keeping business files and schemas unchanged limits compatibility risk and
  separates coordination state from intelligence and review evidence.
- A single Worker mutation owner prevents concurrent export/marking races
  without changing the synchronous Review API contract.

## Consequences

- Web, Worker and Ops have distinct lifecycle responsibilities in one
  Community package and image.
- Community supports one active Worker per runtime-state scope and process-safe
  job/lease coordination.
- Existing top-level compatibility entrypoints, environment aliases, business
  state paths and JSON/JSONL schemas remain supported.
- Runtime coordination data lives in `NARROWCTI_RUNTIME_DB`; it is separate
  from source and review business-state files.
- If a new runtime database is created, it can be backed up or discarded
  separately; existing JSON/JSONL business state remains available to the
  compatibility path.
