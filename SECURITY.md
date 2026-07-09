# Security Policy

NarrowCTI processes threat intelligence, indicators, source metadata and
OpenCTI export material. Security reports must be handled carefully to avoid
leaking credentials, customer data or sensitive feed payloads.

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.8.x | Yes |
| v0.7.x and older | Best effort |

## Reporting a Vulnerability

Do not open a public issue with exploit details, credentials, tokens, private
feed payloads or customer identifiers.

Use GitHub private vulnerability reporting if it is enabled for the repository.
If private reporting is not available, open a public issue with only a high-level
summary and ask maintainers for a private disclosure channel.

Please include:

- affected version or commit;
- affected component;
- impact summary;
- minimal reproduction steps without secrets;
- whether OpenCTI, MISP, Docker or a source connector is involved;
- suggested mitigation if known.

## Sensitive Data Handling

Never attach:

- `.env` files;
- OpenCTI, MISP or OTX API keys;
- raw customer feed exports;
- local `state/` evidence;
- local agent instructions such as `AGENTS.md`.

## Maintainer Response

Maintainers should acknowledge security reports, triage severity, prepare a fix
or mitigation, and publish release notes once the issue can be safely disclosed.

