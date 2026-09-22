# MIG-ADR-012 — Observability and operational evidence

- Status: accepted for W5 / PR-17
- Context: Preflight, diagnostics, correlation, relationship audit and release reports expose operational evidence that must remain auditable without coupling canonical application semantics to gateway composition or transport details.
- Proposed Decision: Place pure reporting, assurance, validation and support-diagnostics semantics in application modules; keep file readers/writers, transport, gateway settings and CLI composition in infrastructure/adapters or compatibility wrappers. Treat report schemas, redaction profiles, provenance and validation findings as versioned contracts.
- Alternatives: Rely on container logs only; expose raw state snapshots by default; keep all reporting semantics in gateway modules.
- Consequences: Support and release validation can be automated without leaking local state or secrets, while legacy gateway entrypoints remain compatible during rollout.
- Dependencies: Current reporting/diagnostics characterization; MIG-ADR-002; MIG-ADR-005; MIG-ADR-010 (proposed); MIG-ADR-011.
- Related ADRs: MIG-ADR-013; MIG-ADR-014; MIG-ADR-015; MIG-ADR-018.
- Target Wave: W5 / PR-17.

This ADR is limited to the W5 / PR-17 reporting, diagnostics and assurance extraction. It does not accept MIG-ADR-010 or MIG-ADR-013, does not move gateway.mitre/core.mitre, and does not change report output contracts beyond preserving them through compatibility wrappers.
