# W0 configuration baseline — v1.1.1

This document records configuration contracts observed in the release tree.
It does not change defaults or reconcile differences between templates, code
and local deployments.

| Area | Code/template baseline | Characterization note |
| --- | --- | --- |
| Gateway dry-run | `NARROWCTI_DRY_RUN=false` in code; `true` in templates | deployment safety posture is explicit |
| MISP transport | `MISP_VERIFY_TLS=false` | production-like deployments should opt into valid TLS verification |
| MISP filtering | `MISP_TAGS=tlp:green` in templates; empty in code | tag/query behavior is source configuration, not a W0 change |
| Graph export | `NARROWCTI_GRAPH_EXPORT_MODE=audit` | `audit`, `dry-run`, and `export` remain explicit modes |
| OpenCTI graph lookup | disabled in templates by default | read-only lookup and fail-open behavior are already tested |
| Quarantine | enabled, score threshold `50` | release requires a reviewer reason by default |
| Contextual scoring | `shadow`, maximum impact `100` | calculated and audited without changing decisions |
| State and evidence | `/app/state` repositories and audit files | state is runtime data and remains untracked |

The full environment contract remains in
[`configuration-reference.md`](configuration-reference.md),
[`environment-profiles.md`](environment-profiles.md) and the deployment
templates. Python version parity, dependency versions, TLS and packaging are
documented as follow-up work and are not modified by W0.
