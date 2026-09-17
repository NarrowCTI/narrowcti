# MIG-ADR-005 — Domain primitives

- Status: proposed
- Context: Candidates, evidence, policy results and decisions are currently represented by mappings and dataclasses across modules.
- Proposed Decision: Identify domain primitives from the characterization outputs before introducing new types.
- Alternatives: Add a broad domain model immediately; preserve unbounded mappings indefinitely.
- Consequences: New primitives will be justified by stable contracts rather than by target architecture alone.
- Dependencies: W0 golden fixtures; ADR-006, ADR-007 and ADR-010.
- Target Wave: W1 architecture foundation; implementation deferred.

This ADR does not add a domain package in W0.
