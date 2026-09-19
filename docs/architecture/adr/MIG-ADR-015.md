# MIG-ADR-015 — Community repository ports and local persistence

- Status: accepted for W2 / PR-06
- Context: The Community runtime currently persists processed-source state,
  artifact fingerprints and graph deduplication data through concrete JSON
  implementations under `core`. The migration needs explicit ports without
  changing processor APIs, state formats or graph semantics.
- Proposed Decision: Introduce minimal structural `Protocol` contracts for
  `StateRepository`, `ArtifactIndex` and `GraphIndex`. The first two receive
  canonical local filesystem implementations under
  `src/narrowcti/adapters/persistence/local`; the existing concrete public
  names `ProcessedItemStateRepository`, `PulseStateRepository`,
  `MISPEventStateRepository` and `ArtifactDeduplicationIndex` remain unchanged
  and are reexported by the legacy `core.*` modules. `GraphIndex` is introduced
  only as a port in PR-06. `GraphDeduplicationIndex` remains the concrete owner
  in `core` because its plan helpers are shared by OpenCTI lookup code.
- Alternatives: Move graph deduplication together with local persistence;
  normalize processors to generic state methods; expose filesystem paths and
  JSON helpers in the ports; or create cosmetic `Local*` implementation names.
- Consequences: Community persistence becomes substitutable without adding a
  commercial dependency or changing current callers. State and artifact JSON
  formats, atomic writes, refresh behavior, fingerprints, sightings and
  timestamps remain compatibility contracts. The application-facing adoption
  of generic `StateRepository` is deferred to a later wave; OTX/MISP continue
  using their historical source-specific methods in this PR.
- Dependencies: MIG-ADR-001, MIG-ADR-002, MIG-ADR-005, MIG-ADR-014 and the
  characterized state, artifact and graph deduplication tests.
- Target Wave: W2 / PR-06 — persistence, artifact and graph ports with local
  adapters.

## PR-06 boundary contract

The ports contain only consumer-facing operations. They do not expose paths,
filesystem access, JSON schemas, `refresh`, load/save helpers or adapter
administrative details.

The current operational order remains:

```text
successful export
→ artifact mark
→ source checkpoint
→ DecisionRecord
→ graph exported-plan mark, when applicable
```

Dry-run and export errors do not mark artifacts or source checkpoints. Artifact
and graph timestamp semantics remain separate; no clock abstraction or format
normalization is introduced in this wave.

OpenCTI lookup, quarantine persistence, source adapters, processors,
`DecisionRecord` and graph deduplication semantics remain outside this PR.
