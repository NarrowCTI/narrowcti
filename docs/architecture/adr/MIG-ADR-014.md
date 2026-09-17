# MIG-ADR-014 — Compatibility and rollout policy

- Status: accepted
- Context: The migration must preserve v1.1.1 behavior while changing package and architecture boundaries over multiple waves.
- Proposed Decision: Require characterization evidence, review and release validation at each wave; use explicit compatibility windows and rollback points.
- Alternatives: Merge all waves into one release; rely on semantic versioning without behavioral evidence.
- Consequences: Each wave has a bounded blast radius and can be rolled back without rewriting protected branches.
- Dependencies: W0 inventory, coverage observation, all preceding ADRs and the documented `chore/* -> dev -> main` flow.
- Target Wave: W0 approval; applies to all subsequent waves.

This record governs the W1 foundation rollout. No release version change or
automatic rollout is implemented by PR-02.
