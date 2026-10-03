# MIG-ADR-014 — Compatibility and rollout policy

- Status: accepted; historical Community 2.0 refactor record
- Context: During the Community 2.0 refactor, package and architecture boundaries changed while preserving the v1.1.1 behavioral baseline.
- Decision: The completed migration used characterization evidence, bounded rollout, compatibility windows, release validation and rollback points.
- Alternatives: Merge all waves into one release; rely on semantic versioning without behavioral evidence.
- Consequences: The completed refactor kept each change bounded and provided rollback points without rewriting protected branches.
- Dependencies: W0 inventory, coverage observation, all preceding ADRs and the documented `chore/* -> dev -> main` flow.
- Historical scope: Accepted during W0 and applied to the completed Community 2.0 migration waves. This ADR does not define future product construction or roadmap work.

This record documents the compatibility and rollout policy used during the
completed refactor. PR-02 did not change the release version or implement an
automatic rollout.
