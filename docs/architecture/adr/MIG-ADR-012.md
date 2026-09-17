# MIG-ADR-012 — Observability and operational evidence

- Status: proposed
- Context: Preflight, diagnostics, correlation, relationship audit and release reports expose operational evidence.
- Proposed Decision: Treat operator-facing evidence files and validation reports as versioned contracts with explicit redaction boundaries.
- Alternatives: Rely on container logs only; expose raw state snapshots by default.
- Consequences: Support and release validation can be automated without leaking local state or secrets.
- Dependencies: W0 configuration baseline; ADR-010 and ADR-011.
- Target Wave: W1 architecture foundation; implementation deferred.

W0 documents the boundary and does not alter report formats.
