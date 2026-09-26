# Analyst Review API

The NarrowCTI analyst review API exposes the quarantine workflow through an
authenticated HTTP boundary. It is an operator API for reviewing, releasing,
rejecting and previewing quarantined decisions. It does not replace or bypass
`AnalystReviewService`: the CLI and HTTP paths use the same repository,
reason policy, export path and append-only audit records.

This document is the current API contract. The v0.8 analyst-review document is
a historical design snapshot.

## Scope And Safety

- The service binds to host loopback by default in Compose.
- Every review route requires a bearer credential; only `/healthz` is public.
- Credential files store SHA-256 token hashes, never raw bearer tokens.
- The authenticated principal, not a request field, is written to review audit
  evidence.
- Raw source snapshots are omitted by default and require `admin` plus
  `include_raw=true`.
- Real OpenCTI export is disabled unless
  `NARROWCTI_REVIEW_API_ALLOW_EXPORT=true` is explicit.
- Interactive documentation is disabled by default.
- HTTP Host values are allow-listed and request bodies are bounded.
- The file-backed service is single-process. Do not scale it horizontally until
  the quarantine and audit repositories use a transactional shared backend.

## Roles And Permissions

| Role | Permissions |
| --- | --- |
| `reader` | Queue summary, record list/detail and audit reads. |
| `reviewer` | Reader access, release, partial release, reject and export preview. |
| `exporter` | Reader access, export preview and explicitly enabled real export. |
| `admin` | All permissions, including raw snapshot access. |

Roles are additive. A principal that both decides and exports must receive both
`reviewer` and `exporter`, or `admin`. The permission names enforced by the
application are `review:read`, `review:decide`, `review:raw`,
`export:preview` and `export:execute`.

## Credential Provisioning

Generate a random token and its hash:

```powershell
python -m gateway.review_auth
```

The command prints the raw token once and its SHA-256 hash. Store the raw token
in a secret manager and put only the hash in the local credential file:

```json
{
  "credentials": [
    {
      "credential_id": "soc-analyst-01",
      "principal": "analyst@example.org",
      "token_sha256": "replace-with-the-generated-64-character-hash",
      "roles": ["reviewer"]
    }
  ]
}
```

Use `deployment/review-api-credentials.example.json` as the schema reference.
Create `deployment/review-api-credentials.json` locally; that filename is
ignored by Git and Docker build context. Mount the file read-only.

## Configuration And Startup

The minimum safe values are:

```text
NARROWCTI_REVIEW_API_DOCS_ENABLED=false
NARROWCTI_REVIEW_API_ALLOW_EXPORT=false
NARROWCTI_REVIEW_API_ALLOWED_HOSTS=127.0.0.1,localhost
NARROWCTI_REVIEW_API_MAX_BODY_BYTES=16384
```

The credential source and published port are Compose host interpolations:

```powershell
$env:NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE = "./review-api-credentials.json"
$env:NARROWCTI_REVIEW_API_PUBLISHED_PORT = "8081"
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile review-api up -d --build narrowcti-review-api
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile review-api ps
```

The default endpoint is `http://127.0.0.1:8081`. Put it behind authenticated
TLS and a restricted reverse proxy before remote access. Do not publish the
container port broadly on an untrusted network.

## HTTP Contract

All JSON error responses use `{"detail":"..."}` unless FastAPI validation
returns its standard structured `detail` list. A missing or invalid bearer
token returns `401` with `WWW-Authenticate: Bearer`; an authenticated caller
without the required permission returns `403`.

| Method | Path | Permission | Successful result |
| --- | --- | --- | --- |
| `GET` | `/healthz` | Public | `200`, liveness JSON only. |
| `GET` | `/api/v1/review/summary` | `review:read` | `200`, queue counts and state summary. |
| `GET` | `/api/v1/review/records` | `review:read` | `200`, bounded record list. |
| `GET` | `/api/v1/review/records/{id}` | `review:read` | `200`, one record without raw snapshot by default. |
| `GET` | `/api/v1/review/audit` | `review:read` | `200`, bounded audit events. |
| `POST` | `/api/v1/review/records/{id}/release` | `review:decide` | `200`, full release result. |
| `POST` | `/api/v1/review/records/{id}/release-indicators` | `review:decide` | `200`, partial release result. |
| `POST` | `/api/v1/review/records/{id}/reject` | `review:decide` | `200`, rejection result. |
| `POST` | `/api/v1/review/records/{id}/export-preview` | `export:preview` | `200`, export candidates with no OpenCTI mutation. |
| `POST` | `/api/v1/review/records/{id}/export` | `export:execute` plus export enabled | `200`, OpenCTI export result. |

### Queue Reads

`GET /api/v1/review/records` accepts:

| Query | Default | Validation |
| --- | --- | --- |
| `status` | `pending` | `all`, `pending`, `released`, `partially-released`, `rejected` or `expired`. |
| `source_key` | empty | Maximum 128 characters. |
| `limit` | `100` | Integer from 1 through 500. |

`GET /api/v1/review/records/{id}` accepts `include_raw=false`. A reader can
inspect the curated record without raw input. `include_raw=true` requires the
`review:raw` permission, currently granted only by `admin`.

`GET /api/v1/review/audit` accepts `quarantine_id`, `action` and `limit` (1 to
500). Audit output is evidence, not a mutable queue and should be retained with
the corresponding decision report.

### Decisions

Release, partial release and reject require a JSON body with a non-blank reason:

```json
{"reason":"Relevant to the monitored financial sector"}
```

Partial release additionally requires a unique, non-empty `indicator_types`
list, for example:

```json
{
  "reason": "Release hashes for hunting; hold URLs for review",
  "indicator_types": ["sha256", "md5"]
}
```

The service returns `404` when the quarantine id does not exist and `409` when
the repository rejects an invalid state transition or reason. A successful
decision appends the authenticated principal and reason to the release audit.

### Export Preview And Export

`export-preview` executes the released-record export path with `dry_run=true`.
It may produce STIX candidates and deduplication decisions, but it does not
call OpenCTI for a mutation. Use it before enabling real export.

`export` requires both an `exporter` or `admin` principal and
`NARROWCTI_REVIEW_API_ALLOW_EXPORT=true`. Missing `OPENCTI_URL` or
`OPENCTI_TOKEN`, or an invalid OpenCTI configuration, returns `503`. Export
deduplication and the normal graph policy remain active; review approval does
not bypass TLP, age, provenance, score or graph policy controls.

## Curl Examples

```powershell
$headers = @{ Authorization = "Bearer $env:NARROWCTI_REVIEW_TOKEN" }
Invoke-RestMethod -Method Get `
  -Uri "http://127.0.0.1:8081/api/v1/review/summary" `
  -Headers $headers

$body = @{ reason = "Relevant to monitored scope" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8081/api/v1/review/records/<id>/release" `
  -Headers $headers -ContentType "application/json" -Body $body
```

Expected negative checks for a controlled validation are:

```text
GET /healthz without a token                                  -> 200
GET /api/v1/review/summary without a token                    -> 401
GET /api/v1/review/summary with a reader token                -> 200
POST /.../release with a reader token                         -> 403
POST /.../release with an empty or unknown JSON field          -> 422
POST /.../export while allow-export=false                     -> 403
POST /.../export with missing OpenCTI connection settings     -> 503
```

## Audit And Evidence

Release, partial release, reject and export transitions append to
`NARROWCTI_RELEASE_AUDIT_FILE`. API exports identify the executor as
`review-api:<authenticated principal>`. The API never accepts caller-supplied
reviewer or exporter identities. Preserve the summary, queue snapshot, audit
events, export preview and final OpenCTI audit together for a reproducible
review record.

## DAST And Test Expectations

`.github/workflows/dast.yml` builds a disposable API image and state directory,
creates a temporary masked credential, verifies `401` and authenticated `200`
behavior, then runs the pinned OWASP ZAP `2.17.0` OpenAPI scan. The workflow
uploads JSON, HTML and Markdown evidence and removes its container and network
even when the scan fails.

The local API contract test should cover authentication, role boundaries,
request validation, raw snapshot protection, state transitions, preview-only
behavior and export configuration errors. DAST evidence does not replace the
OpenCTI end-to-end graph validation described in
`opencti-coverage-matrix.md`.
