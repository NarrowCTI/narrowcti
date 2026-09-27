# Community 2.0 compatibility migration

This document records the bounded W7 / PR-22 compatibility cutover. It does
not set a removal date for the supported top-level legacy roots.

| Legacy / transitional path | Canonical replacement | Status | Compatibility treatment | Notes |
| --- | --- | --- | --- | --- |
| `core.*` | `narrowcti.domain.*`, `ports.*`, `application.*`, or the established adapter owner | SUPPORTED COMPATIBILITY | Top-level imports remain available through the documented 2.x window | Some modules still own residual behavior and require a later migration wave |
| `connectors.misp.*` | `narrowcti.adapters.sources.misp.*` where an owner exists | SUPPORTED COMPATIBILITY | MISP processor and feed adapter remain unchanged | Source runtime cutovers are outside PR-22 |
| `connectors.otx.*` | No complete 1:1 replacement for the current processor | MANUAL MIGRATION REQUIRED | Top-level package remains supported | `connectors/otx/connector.py` also preserves a historical script entrypoint |
| `exporters.*` | `narrowcti.adapters.opencti.*` / `narrowcti.adapters.stix.*` | SUPPORTED COMPATIBILITY | Legacy exporters remain importable | Graph/STIX behavior is unchanged |
| `gateway.*` | `narrowcti.cli.*`, `narrowcti.api.*`, `narrowcti.application.*` where already migrated | SUPPORTED COMPATIBILITY | Current Docker, Compose, DAST and operator entrypoints remain valid | Gateway modules are still active delivery surfaces |
| `narrowcti.core.*` | Corresponding canonical owner | REMOVED TRANSITIONAL SHIM | Nested facade packages were removed by PR-22 | Use the top-level legacy root during the compatibility window |
| `narrowcti.connectors.*` | Corresponding canonical owner | REMOVED TRANSITIONAL SHIM | Nested facade packages were removed by PR-22 | No runtime contract was published for these paths |
| `narrowcti.exporters.*` | Corresponding canonical owner | REMOVED TRANSITIONAL SHIM | Nested facade packages were removed by PR-22 | No runtime contract was published for these paths |
| `narrowcti.gateway.*` | Corresponding canonical owner | REMOVED TRANSITIONAL SHIM | Nested facade packages were removed by PR-22 | No runtime contract was published for these paths |

The removed nested facades were not present in the published Community v1.1.1
source tree. `narrowcti.compat` was their implementation detail and is removed
with them. Historical documents retain their original paths as immutable
evidence. New code must use canonical `narrowcti.*` owners, and exceptions are
governed by the architecture boundary allowlist and tests.

The migration checker at `scripts/check_2_0_migration.py` is read-only and
deterministic. It reports legacy imports as warnings, removed nested paths as
errors, and uses `manual migration required` when no safe one-to-one mapping
exists. Top-level aliases are retained through the documented 2.x
compatibility/deprecation window; no future removal date is defined here.
