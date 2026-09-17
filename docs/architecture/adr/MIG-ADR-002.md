# MIG-ADR-002 — Source-tree and package boundary

- Status: accepted
- Context: v1.1.1 has top-level `core`, `connectors`, `exporters` and `gateway` packages without a `src/` layout. The first W1 packaging step must make this flat layout installable without changing import paths or moving modules.
- Proposed Decision: PR-02 makes the current flat layout installable and restricts package discovery explicitly to `connectors*`, `core*`, `exporters*` and `gateway*`. No module is moved in PR-02. The migration to `src/` and its compatibility imports are reserved exclusively for PR-03.
- Alternatives: Use unrestricted automatic discovery; move the tree during PR-02; infer package boundaries from directory names at build time.
- Consequences: The wheel contains only the four current runtime package families, existing imports remain stable, and PR-03 can introduce `src/` with a separately reviewed compatibility layer. `tests`, `docs`, `scripts`, `deployment`, `state` and local artifacts are excluded from the package.
- Dependencies: W0 inventory and characterization; MIG-ADR-001 and MIG-ADR-014; PR-03 for the later `src/` migration.
- Target Wave: W1 / PR-02 package foundation; `src/` migration is W1 / PR-03.

This accepted record authorizes only the PR-02 flat-layout packaging step; it
does not authorize a package move or compatibility shim.
