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
  sys.modules["narrowcti.core.feed_contract"]` illustrates the identity guarantee
  for mapped modules belonging to the supported import contract, after both
  names have been imported in either order. `connectors.otx.connector` is an
  explicit exception: it remains a historical script-entrypoint invoked as
  `python connector.py` in the OTX image. Its unqualified local imports mean
  neither `import connectors.otx.connector` nor
  `import narrowcti.connectors.otx.connector` is part of the supported package
  import contract. The facade preserves that existing limitation without a
  runtime workaround. Source-mode uses `PYTHONPATH=/app/src:/app`; an installed
  wheel contains both canonical facades and legacy packages.
- Dependencies: PR-02 package foundation, MIG-ADR-001 and MIG-ADR-014.
- Target Wave: W1 / PR-03.

The compatibility window remains in force until a later migration release
provides replacement paths, deprecation evidence and automated removal tests.
Legacy imports and CLI module entrypoints remain supported during the window
where they are currently importable. The OTX connector remains a documented
historical script-entrypoint exception until a dedicated migration decision
addresses its unqualified local imports; removing or rewriting that contract
is outside PR-03 and requires a separate approved decision.

## PR-05 addendum — domain primitive ownership

- Status: accepted for W1 / PR-05
- Context: PR-05 moves selected pure intelligence primitives from the legacy
  `core` implementation locations into `src/narrowcti/domain/intelligence`.
  The existing `narrowcti.core.*` facade and legacy import contract must remain
  stable while the domain becomes the single owner of migrated logic.
- Proposed Decision: The domain modules are the canonical owners for the
  selected PR-05 symbols. The corresponding `core.*` modules reexport those
  exact objects and retain any explicitly deferred symbols, including
  `FeedAdapter` and `FeedRunSummary`. The existing explicit facade table and
  module identity guarantee remain unchanged for mapped legacy modules. No
  `MetaPathFinder`, global import hook, filesystem traversal or `sys.path`
  mutation is introduced.
- Alternatives: Duplicate domain and legacy implementations; alias only
  package families; move adapters and application orchestration together with
  the primitives.
- Consequences: Legacy callers continue to import the same public symbols,
  while new code can use the domain namespace. The domain-to-core dependency
  direction is prohibited; compatibility flows from legacy wrappers to the
  canonical domain implementation. `FeedAdapter`, `FeedRunSummary`,
  `DecisionRecord`, `DecisionAuditLog` and the OTX historical script remain
  outside this migration.
- Dependencies: MIG-ADR-001, MIG-ADR-005 and MIG-ADR-014.
- Target Wave: W1 / PR-05.

## PR-06 addendum — persistence compatibility boundary

- Status: accepted for W2 / PR-06
- Context: PR-06 introduces explicit persistence ports and local adapters while
  the legacy `core` import surface remains supported.
- Proposed Decision: `core.atomic_io`, `core.state_repository` and
  `core.deduplication` reexport the exact canonical concrete objects owned by
  the local persistence adapters. The historical public names
  `ProcessedItemStateRepository`, `PulseStateRepository`,
  `MISPEventStateRepository` and `ArtifactDeduplicationIndex` are preserved.
  `core.graph_deduplication` is intentionally not relocated: its concrete
  `GraphDeduplicationIndex` and shared plan helpers remain in `core` while the
  new `GraphIndex` port is characterized structurally.
- Alternatives: Rename implementations to `Local*`; add family aliases;
  move graph deduplication into filesystem adapters; normalize OTX/MISP to
  generic state methods in this PR.
- Consequences: Legacy imports and object identity remain stable, local state
  ownership becomes explicit for state and artifacts, and graph/OpenCTI lookup
  does not acquire a conceptual dependency on local persistence.
- Dependencies: MIG-ADR-005 and the PR-03 compatibility window.
- Related ADR: MIG-ADR-015 defines the accepted W2 persistence-port boundary
  that this addendum applies when the PR-06 implementation is introduced.
- Target Wave: W2 / PR-06.
