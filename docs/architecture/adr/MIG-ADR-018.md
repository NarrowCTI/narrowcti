# MIG-ADR-018 — Gateway runtime and source provider registry boundary

- Status: accepted for W5 / PR-15
- Context: The Community gateway currently combines scheduler behavior, one-cycle
  execution, source registry state, concrete MISP/OTX/OpenCTI composition,
  GatewaySettings loading and the OpenCTI client under `gateway.*`. PR-15 must
  establish canonical owners without changing source processing, query/run,
  persistence, graph, quarantine or export semantics.
- Proposed Decision: Make `application.runtime` a scheduler-neutral one-cycle
  runtime and `application.provider_registry` the owner of the minimal lazy
  `SourceDefinition`, `SourceRegistry` and `normalize_source_key` contracts.
  Concrete MISP, OTX, OpenCTI, deduplication and persistence composition remains
  in infrastructure. The Community scheduling loop remains owned by the CLI
  composition root. `GatewaySettings` moves to the canonical infrastructure
  configuration owner and the OpenCTI client moves to the canonical OpenCTI
  adapter. Historical gateway entrypoints remain compatibility surfaces.
  No CapabilityRegistry, entitlement behavior, plugin discovery, dynamic
  provider loading, generic SourceAdapter port or scheduler framework is
  introduced.
- Alternatives: Keep gateway modules as permanent mixed owners; put concrete
  source composition in application; invent a generic provider/plugin registry;
  or move the infinite scheduler loop into the application runtime. These
  alternatives either violate dependency direction, make inactive sources
  require credentials, or couple Community to future commercial capability
  concerns.
- Consequences: One-cycle execution can be tested independently of scheduling
  and concrete providers. Source factories remain lazy, the shared artifact
  deduplication index remains shared, and summary JSONL persistence remains an
  infrastructure side effect after summary logging. Legacy imports and the
  `gateway.connector` monkeypatch surface are preserved behaviorally.
- Dependencies: Current gateway runtime/source/settings/OpenCTI
  characterization; MIG-ADR-003; MIG-ADR-008; MIG-ADR-014; MIG-ADR-016.
- Related ADRs: MIG-ADR-004; MIG-ADR-015.
- Target Wave: W5 / PR-15.

