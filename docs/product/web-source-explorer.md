# Community Web and Source Explorer

The Community Web role combines the browser UI and bearer-authenticated Review
API in one process:

```text
python -m narrowcti.cli.web
```

The browser never calls MISP, OTX or OpenCTI directly. Source search and detail
are transient, bounded Web-to-application-to-provider operations. Preview,
dry-run and run-once are explicit jobs submitted to the shared `JobRepository`
and executed by the Worker using its own source credentials.

## Start the Web role

Create a local credential file using the schema in
`deployment/review-api-credentials.example.json`. Generate a random token and
hash with `python -m gateway.review_auth`; keep the raw token in a password
manager and store only the hash in the JSON file. Use a reviewer/admin role for
the browser; the same credential remains a bearer credential for
`/api/v1/review/*`.

```powershell
Copy-Item deployment\web.env.example deployment\web.env
Copy-Item deployment\review-api-credentials.example.json deployment\review-api-credentials.json
$env:NARROWCTI_WEB_ENV_FILE = "./web.env"
$env:NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE = "./review-api-credentials.json"
$env:NARROWCTI_WEB_PUBLISHED_PORT = "8081"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile web up -d --build narrowcti-web
```

The example credential hash is intentionally unusable. Replace it before
starting the service. Compose publishes only to loopback by default. Put remote
access behind an explicitly configured TLS-terminating reverse proxy and set
the accepted host names in `NARROWCTI_WEB_ALLOWED_HOSTS`; forwarded headers are
not trusted implicitly. If the proxy terminates TLS and forwards HTTP, also set
the exact external origin in `NARROWCTI_WEB_PUBLIC_ORIGIN` so browser Origin
validation remains same-origin without trusting `X-Forwarded-*` headers.

## Dedicated Explorer credentials

Explorer credentials are a separate read-only integration identity and are
never inherited from `MISP_KEY` or `OTX_API_KEY`. Missing credentials make the
provider unavailable without preventing the Web role from starting.

For MISP, set `NARROWCTI_WEB_MISP_URL` and
`NARROWCTI_WEB_MISP_KEY_FILE` in `web.env`, then mount a dedicated API key
read-only using the optional MISP overlay:

```powershell
$env:NARROWCTI_WEB_MISP_KEY_SOURCE = "./web-misp-readonly-key.txt"
docker compose `
  -f deployment\docker-compose.narrowcti-gateway.yml `
  -f deployment\docker-compose.narrowcti-web-misp.yml `
  --profile web up -d narrowcti-web
```

The MISP identity should have only the provider-side read permissions needed
for event search/detail. TLS verification defaults to enabled; an invalid TLS
setting fails closed.

For OTX, set `NARROWCTI_WEB_OTX_KEY_FILE` and use the optional OTX overlay:

```powershell
$env:NARROWCTI_WEB_OTX_KEY_SOURCE = "./web-otx-explorer-key.txt"
docker compose `
  -f deployment\docker-compose.narrowcti-gateway.yml `
  -f deployment\docker-compose.narrowcti-web-otx.yml `
  --profile web up -d narrowcti-web
```

Prefer a dedicated OTX key operationally. This application does not claim that
the upstream service provides per-key read-only permission granularity.

## Governed operations

| Operation | Execution | Effects |
| --- | --- | --- |
| Search/detail | Web request | Transient, bounded provider read; no job or persistence. |
| Preview | Worker job | Uses the real ingestion policy path; no decision audit, quarantine, artifact mark, checkpoint, graph mark or export. The coordination job row is retained. |
| Dry-run | Worker job | Uses the governed dry-run path. Existing local DecisionRecord and quarantine behavior may occur; no OpenCTI export, successful artifact mark or source checkpoint. |
| Run once | Worker job | Real bounded ingestion using Worker credentials; Admin-only and limited to one active Community job globally. |

Every evaluation job stores only `source_key`, `external_id`, the expected
revision fingerprint, request ID and requester. The Worker refetches the
source document with its own credentials and fails closed if the fingerprint
changed. A reclaimed attempt is marked `execution_ambiguous`; it is never
automatically replayed.

## Sessions and browser protections

The Web process stores opaque 32-byte random session identifiers and CSRF
secrets in memory. Bearer tokens are validated and discarded; they are not
stored in sessions or browser storage. Restarting Web invalidates sessions.
Production cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, host-only and
`Path=/`. `NARROWCTI_WEB_COOKIE_SECURE=false` is permitted only for local HTTP
development.

Every unsafe browser request, including HTMX requests, requires a session-bound
CSRF token and rejects cross-origin `Origin`/Fetch Metadata. The bearer API
continues to accept bearer credentials only. Responses use a strict same-origin
CSP and security headers. Request bodies, source responses, query sizes,
results, concurrent calls and per-session search rates are bounded.

See `analyst-review-api.md` for the JSON API contract and
`configuration-reference.md` for the complete environment-variable reference.
