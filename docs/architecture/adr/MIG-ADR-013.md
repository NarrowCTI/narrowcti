# MIG-ADR-013 — Community and Enterprise separation

- Status: proposed
- Context: The repository is the Community Edition baseline while the migration documents distinguish future commercial capabilities.
- Proposed Decision: Keep Community behavior and licensing boundaries explicit; do not introduce Enterprise-only dependencies into Community waves.
- Alternatives: Mix roadmap features into the refactor; hide Enterprise assumptions in shared runtime code.
- Consequences: Community releases remain independently buildable, testable and auditable.
- Dependencies: Product/engineering blueprint and migration plan; ADR-001 and ADR-014.
- Target Wave: W0 governance; applies to all waves.

This ADR does not add feature gates or commercial code.
