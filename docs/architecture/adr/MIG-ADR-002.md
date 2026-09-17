# MIG-ADR-002 — Source-tree and package boundary

- Status: proposed
- Context: v1.1.1 has top-level `core`, `connectors`, `exporters` and `gateway` packages without a `src/` layout.
- Proposed Decision: Define the future package boundary from observed imports and contracts before moving files.
- Alternatives: Move the tree immediately; infer boundaries only from directory names.
- Consequences: Existing imports remain stable during W0 and the later move can be staged.
- Dependencies: W0 inventory; ADR-004 and ADR-005.
- Target Wave: W1 planning; implementation deferred.

This skeleton records a decision surface only; no package move is included.
