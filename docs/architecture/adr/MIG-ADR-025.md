# MIG-ADR-025 — Runtime Role Foundation

- Status: accepted for W8 / PR-23
- Date: 2026-09-27
- Scope: Community 2.0 runtime foundation
- Depends on: MIG-ADR-002, MIG-ADR-003, MIG-ADR-014, MIG-ADR-015, MIG-ADR-018, MIG-ADR-022, MIG-ADR-024
- Related ADRs: MIG-ADR-010, MIG-ADR-013, MIG-016, MIG-ADR-019, MIG-ADR-020

## Context

The Community distribution already provides a long-running gateway, a review
API and one-shot operational commands from one package and image. Their
lifecycles currently share broad configuration and local JSON/JSONL state,
while the supported Community topology is one active ingestion Worker, a Web
or API process and one-shot Ops commands.

The existing JSON/JSONL business state remains part of the compatibility
contract, but it does not provide a general cross-process claim, lease or
mutation guarantee. PR-23 must establish the runtime-role and coordination
foundation before the Web UI and future scheduled execution are introduced.

## Decision

PR-23 establishes a modular-monolith runtime foundation with explicit Web/API,
Worker and Ops roles. All roles use the same package, wheel, image and
version. The Community baseline supports one active Worker per runtime state
scope; the Worker lifecycle owns a process-safe lease and legacy
`gateway.connector` delegates to it.

The application layer receives role and job contracts through inward-safe
ports. It does not import infrastructure, concrete adapters, FastAPI or
Docker. A minimal `JobRepository` exposes idempotent submission, atomic
pending-to-running claim, owner/attempt-fenced completion and failure. A
separate Worker lease contract and a focused process-coordination contract
share one local SQLite runtime-store adapter.

SQLite is the preferred Community local implementation because it provides
transactional claims, uniqueness, lease ownership, crash recovery and
cross-platform local/Docker-volume behavior through the Python standard
library. The runtime database contains only jobs, leases, coordination
metadata and schema metadata. Existing checkpoints, quarantine, release audit,
artifact/graph indexes, decision audit and summaries remain JSON/JSONL and
retain their schemas.

Quarantine/release mutations retain synchronous API behavior and are
serialized with a cross-process coordination boundary. Real artifact export
and artifact marking have one Worker mutation owner; the Review API remains a
synchronous bounded command facade. No Web UI, Scheduler, broker,
multi-worker Community runtime, commercial persistence or domain semantic
rewrite is introduced.

## Alternatives considered

- Keep documentation-only one-worker behavior: rejected because two processes
  can currently start and race on local state.
- Use JSON/JSONL as the JobRepository: rejected because they cannot provide
  transactional claims, uniqueness and lease recovery.
- Use an ad hoc filesystem lock: possible, but it requires more custom stale
  lock and cross-platform handling than the local SQLite adapter.
- Route every quarantine transition asynchronously through a Worker: rejected
  for PR-23 because it would alter synchronous Review API availability and
  failure semantics.
- Introduce a broker, Scheduler or external database: deferred to
  Professional/Enterprise waves.

## Consequences

- Web, Worker and Ops lifecycle responsibilities become explicit without
  splitting the product into microservices.
- Existing top-level compatibility entrypoints, environment aliases, state
  paths and JSON/JSONL schemas remain supported.
- Community obtains process-safe job claims, Worker ownership and shared-write
  coordination without migrating business state.
- The runtime SQLite file requires a local filesystem or validated Docker
  volume; arbitrary NFS/SMB semantics are not declared supported.
- Artifact export is serialized through the Worker while preserving a
  synchronous public facade and existing OpenCTI reconciliation behavior.
- Professional may add Scheduler and durable scheduling; Enterprise may add
  transactional persistence and worker pools after the Community contracts are
  proven.

## Validation and rollout

Validation includes process-level tests for duplicate submission, atomic claim,
lease expiry, stale-owner fencing, crash recovery, quarantine coordination,
artifact-export races and role isolation. Wheel and container validation must
prove that Web, Worker, Ops and legacy compatibility entrypoints run from the
same installed package/image. Existing full suite, architecture, security,
SBOM and DAST gates remain required.

Rollback is additive: reverting PR-23 leaves existing JSON/JSONL state and the
legacy gateway path usable. A new `runtime.db` is backed up or discarded
separately from business state.

## Target wave

W8 / PR-23 — Runtime Role Foundation.

PR-24 consumes these contracts for the Community Basic Web UI and Source
Explorer. MIG-ADR-020 remains reserved for that Web architecture decision.
