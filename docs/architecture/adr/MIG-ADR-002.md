# MIG-ADR-002 — Source-tree and package boundary

- Status: accepted
- Context: v1.1.1 has top-level `core`, `connectors`, `exporters` and `gateway` packages without a `src/` layout. The first W1 packaging step must make this flat layout installable without changing import paths or moving modules.
- Proposed Decision: PR-02 makes the current flat layout installable and restricts package discovery explicitly to `connectors*`, `core*`, `exporters*` and `gateway*`. No module is moved in PR-02. The migration to `src/` and its compatibility imports are reserved exclusively for PR-03.
- Alternatives: Use unrestricted automatic discovery; move the tree during PR-02; infer package boundaries from directory names at build time.
- Consequences: The wheel contains only the four current runtime package families, existing imports remain stable, and PR-03 can introduce `src/` with a separately reviewed compatibility layer. `tests`, `docs`, `scripts`, `deployment`, `state` and local artifacts are excluded from the package.
- Dependencies: W0 inventory and characterization; MIG-ADR-001 and MIG-ADR-014; PR-03 for the later `src/` migration.
- Target Wave: W1 / PR-02 package foundation; `src/` migration is W1 / PR-03.

## PR-03 addendum — canonical namespace bootstrap

- Status: accepted for W1 / PR-03
- Context: PR-03 introduces `src/narrowcti` while current implementations and
  public imports remain in the four top-level package families.
- Proposed Decision: Add one deterministic facade module for every current
  runtime submodule. A facade imports its explicitly mapped legacy target and
  binds the canonical name in `sys.modules` to that exact object. The reverse
  order is supported because both paths resolve through the same legacy module;
  no family-only alias, `MetaPathFinder`, filesystem traversal, `sys.path`
  mutation or generic import hook is permitted.
- Alternatives: Alias only package families; eagerly import and register every
  module from `__init__`; move all implementations immediately; use a generic
  import hook.
- Consequences: `sys.modules["core.feed_contract"] is
  sys.modules["narrowcti.core.feed_contract"]` is guaranteed for every
  mapped module. Source-mode works with `PYTHONPATH=/app/src:/app`; an
  installed wheel contains both canonical facades and legacy packages. The
  legacy OTX script entrypoint remains a historical script contract and is not
  rewritten by this PR.
- Dependencies: PR-02 package foundation, MIG-ADR-001 and MIG-ADR-014.
- Target Wave: W1 / PR-03.

The compatibility window remains in force until a later migration release
provides replacement paths, deprecation evidence and automated removal tests.
Legacy imports and CLI module entrypoints remain supported during the window
where they are currently importable. The OTX connector remains a documented
historical script-entrypoint exception until a dedicated migration decision
addresses its unqualified local imports; removing or rewriting that contract
is outside PR-03 and requires a separate approved decision.
