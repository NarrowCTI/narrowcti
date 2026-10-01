# MIG-ADR-026 — Community deployment bootstrap and provider readiness

- Status: accepted for W9 / PR-26
- Context: The Community runtime has explicit Web, Worker and Ops roles, but a
  reproducible local deployment still needs a declared Compose layer set,
  role-specific Explorer credentials, truthful provider readiness and process
  exit semantics for bounded run-once execution.
- Decision: Preserve the Web / Worker / Ops split and the existing JobRepository
  handoff. Keep static Gateway preflight deterministic and network-free. Add a
  separate application-owned provider-readiness contract with the fixed public
  states `not_configured`, `credential_missing`, `unreachable`, `tls_failed`,
  `auth_rejected`, `rate_limited`, `degraded` and `ready`; bounded MISP/OTX
  adapters perform non-mutating, non-redirecting probes and never retain response
  bodies. Ops exposes the same application contract as a one-shot diagnostic;
  authenticated Web may invoke it only through an explicit, CSRF-protected,
  rate-limited operator action. Readiness results are not persisted or inferred
  from configuration. Web continues to receive only dedicated read-only
  Explorer secret mounts and never receives `gateway.env`.

  Liveness remains independent of provider, Worker and snapshot state. Gateway
  run-once returns exit code 0 only when all enabled source executions succeed,
  exit code 2 when the bounded cycle completes with one or more source failures,
  and the existing exit code 75 when the Worker lease is unavailable. The
  continuous Worker continues after transient source failures.

  Local shared-network deployment is declarative and optional. NarrowCTI may
  join a pre-existing external integration network but does not own, recreate
  or imperatively connect third-party MISP/OpenCTI stacks. Preflight and
  Operational Validation snapshots remain published by their authoritative
  Ops workflows and read-only from Web.
- Alternatives: Treat configuration presence as provider health; add network
  I/O to static preflight or `/healthz`; merge Gateway credentials into Web;
  spawn Worker containers from Web; or imperatively alter third-party network
  membership. These options blur role authority, leak credentials or make
  deployment non-reproducible.
- Consequences: Operators can distinguish liveness, offline configuration,
  explicit provider readiness and captured operational evidence. Compose layers
  state optional networks and provider secrets explicitly. No scheduler,
  worker pool, commercial feature, external identity provider or source
  lifecycle UI is introduced.
- Dependencies: MIG-ADR-003; MIG-ADR-018; MIG-ADR-020; MIG-ADR-022; MIG-ADR-025;
  current run-once, preflight, Source Explorer and deployment characterization.
- Related ADRs: MIG-ADR-012; MIG-ADR-015; MIG-ADR-024.
- Target Wave: W9 / PR-26.
