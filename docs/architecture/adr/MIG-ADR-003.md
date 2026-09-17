# MIG-ADR-003 — Configuration ownership and typed boundary

- Status: proposed
- Context: Configuration defaults are distributed across code, environment templates and deployment files.
- Proposed Decision: Establish one typed configuration boundary with explicit precedence and compatibility rules before implementation.
- Alternatives: Keep reading environment variables at every call site; normalize configuration during the W0 inventory.
- Consequences: Later configuration work can be tested without changing current defaults in W0.
- Dependencies: W0 configuration baseline; ADR-002 and ADR-014.
- Target Wave: W1 architecture foundation; implementation deferred.

No environment variable or runtime default is changed by this skeleton.
