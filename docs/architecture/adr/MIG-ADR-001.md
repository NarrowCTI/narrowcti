# MIG-ADR-001 — Community migration principles

- Status: proposed
- Context: The v1.1.1 Community release is the immutable behavioral baseline for the Community 2.0 migration.
- Proposed Decision: Preserve observable behavior first, characterize before refactoring, and advance through small reviewed waves.
- Alternatives: Rewrite the runtime in one step; defer characterization until after refactoring.
- Consequences: Migration work is slower initially but regressions remain attributable and reviewable.
- Dependencies: W0 inventory, test matrix, release evidence and the migration plan.
- Target Wave: W0 approval; applies to all subsequent waves.

This record is a proposal only. It does not change runtime behavior.
