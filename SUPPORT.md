# Support

NarrowCTI Community Edition is an open source project. Community support is
best-effort and should stay safe for public collaboration.

## Before Opening an Issue

Check the product documentation first:

- `README.md`
- `docs/README.md`
- `docs/product-reference.md`
- `docs/getting-started.md`
- `docs/deployment-operations.md`
- `docs/configuration-reference.md`
- `docs/opencti-coverage-matrix.md`
- `docs/release-v1.0.0.md` (in development)

For local deployment problems, include the NarrowCTI version, enabled sources,
runtime mode, relevant environment variable names without values, and sanitized
logs.

## Bug Reports

Use the bug report issue template when NarrowCTI behaves differently from the
documented behavior.

Useful bug evidence includes:

- NarrowCTI version or commit;
- source adapter involved, such as OTX or MISP;
- OpenCTI and MISP versions when relevant;
- Docker image tag or local execution command;
- sanitized logs and preflight output;
- expected behavior and actual behavior;
- whether the issue affects graph hygiene, scoring, deduplication, quarantine,
  export or reporting.

Do not include `.env` files, API keys, raw customer payloads, local `state/`
files or private lab instructions.

## Feature Requests

Use the feature request template for new source adapters, curation logic,
graph mappings, scoring improvements, reports, deployment templates or
operator workflows.

Good feature requests explain the CTI value, source evidence available, expected
OpenCTI object or relationship outcome, and how graph hygiene should be
protected.

## Operational Questions

Open a documentation issue when the product docs are unclear or missing an
operator path. For general local troubleshooting, provide enough sanitized
context for maintainers to reproduce the environment safely.

## Security

Do not disclose vulnerabilities publicly before maintainers can triage them.
Follow `SECURITY.md` for private disclosure guidance.

## Commercial Support

No commercial support channel is defined for this community repository. Support
for the public project is provided through the documented community workflow;
do not include private strategy, customer data, credentials or raw feed payloads
in public requests.
