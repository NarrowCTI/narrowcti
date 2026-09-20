# MIG-ADR-003 — Configuration ownership and typed boundary

- Status: accepted
- Context: Runtime configuration is currently assembled by independent Gateway, MISP, OTX, Review API and CLI loaders. Those loaders read overlapping legacy and `NARROWCTI_*` environment variables, apply surface-specific precedence, and expose source credentials alongside operational settings. The PR-04 baseline must preserve those contracts while making precedence, activation scope, TLS defaults and redaction explicit.
- Proposed Decision: Introduce a dependency-free, composable typed configuration boundary in `core.runtime_config`. Core resolvers accept `Mapping[str, str]`; public loaders may use `os.environ` only as their adapter when called without arguments. Existing surface loaders remain the owners of their current precedence rules, and those rules are documented and tested rather than silently normalized across Gateway, MISP and OTX. Required credentials are validated only when the consuming source or service is active. `MISP_VERIFY_TLS` is parsed strictly and fail-closed: absent is `True`, `true/1/yes` is `True`, `false/0/no` is `False`, and any other value is a configuration error. Secret fields are structurally redacted (`repr=False` and safe-dictionary APIs); preflight, diagnostics, reports and JSON may consume only explicit safe representations. OpenCTI connection data used by runtime services crosses the typed boundary; bounded CLI-only environment reads remain documented exceptions.
- Alternatives: Keep reading environment variables at every runtime call site; normalize all legacy and `NARROWCTI_*` precedence globally; add a third-party settings dependency; or make every source credential mandatory at process startup. These alternatives either risk compatibility regressions, add unnecessary runtime dependencies, or make inactive integrations prevent unrelated services from starting.
- Consequences: Configuration behavior becomes auditable and testable without changing the current source-specific contracts. Secure MISP TLS is the default, while an explicit insecure override is visible to preflight/diagnostics. Safe representations can be emitted without leaking canary or production secrets. Some CLI-only reads remain temporarily bounded and documented until later architecture waves. No packaging, Docker/Compose, ports, domain, adapters or W2 behavior is changed by PR-04.
- Dependencies: MIG-ADR-001; MIG-ADR-002; MIG-ADR-014; W0 configuration baseline and characterization tests.
- Target Wave: W1 / PR-04 — typed configuration and secure TLS defaults.

The active precedence matrix and direct-environment-read inventory are maintained in the PR-04 configuration documentation and contract tests. Historical/versioned documents are not rewritten.

## PR-15 addendum — GatewaySettings owner

The canonical owner of GatewaySettings and its existing loader/helpers is
`src/narrowcti/infrastructure/config/settings.py`. The compatibility module
`gateway.settings` continues to expose the historical API. This is an ownership
move only: aliases, defaults, activation scope, precedence and validation
behavior remain unchanged.
