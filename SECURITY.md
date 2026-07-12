# Security Policy

NarrowCTI processes threat intelligence, indicators, source metadata and
OpenCTI export material. Security reports must be handled carefully to avoid
leaking credentials, customer data or sensitive feed payloads.

## Supported Versions

| Version | Supported |
| --- | --- |
| v1.0.0-dev.0 | Development validation line |
| v0.9.x | Yes, latest stable line |
| v0.8.x | Best effort |
| v0.7.x and older | Unsupported |

The current stable minor release is the primary supported line. The v1.0
development line is tested continuously but must not be represented as a stable
release until its tag and GitHub Release exist. Older lines receive only the
support described above unless a maintainer explicitly publishes a backport.

## Reporting a Vulnerability

Do not open a public issue with exploit details, credentials, tokens, private
feed payloads or customer identifiers.

Use GitHub private vulnerability reporting when it is enabled for the
repository. If it is not available, contact the repository owner through a
private channel and do not publish exploit details. A public issue is only a
last-resort pointer to the private process, never the place for a proof of
concept or credentials.

Please include:

- affected version or commit;
- affected component;
- impact summary;
- minimal reproduction steps without secrets;
- whether OpenCTI, MISP, Docker or a source connector is involved;
- suggested mitigation if known.

Useful report categories include:

- credential or token leakage;
- unsafe `.env`, state or support bundle exposure;
- OpenCTI graph pollution caused by malformed or malicious source payloads;
- source adapter behavior that bypasses TLP, score, quarantine or dedup policy;
- container image, dependency or build pipeline weaknesses;
- denial-of-service conditions caused by unbounded feed ingestion.

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

Target response expectations:

- acknowledge receipt within 72 hours when maintainers are available;
- validate impact and affected versions before public disclosure;
- prepare a patch, mitigation or configuration workaround;
- publish security release notes after users have a reasonable upgrade path;
- credit reporters when requested and appropriate.

NarrowCTI does not currently operate a bug bounty program. Security fixes are
handled through coordinated disclosure and public release notes.

## Maintainer Access

Security reports are handled by the repository owner and any explicitly
delegated security maintainer. Community contributors may inspect public code
and submit fixes, but do not receive security settings, release credentials or
direct push access by default.
