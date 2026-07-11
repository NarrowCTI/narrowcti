# Analyst Review API

The NarrowCTI v0.9 analyst review API exposes the existing quarantine review
service through an authenticated HTTP boundary. It does not replace or bypass
`AnalystReviewService`; CLI and HTTP transitions use the same repository,
reason policy, export path and audit records.

## Security Model

- The service binds to host loopback by default in Compose.
- Every review route requires a bearer credential; only `/healthz` is public.
- Credential files store SHA-256 token hashes, not raw bearer tokens.
- Bearer hashes are compared with `hmac.compare_digest`.
- The principal written to review audit evidence comes from the authenticated
  credential and cannot be supplied in a request body.
- Request models reject unknown fields and blank decision reasons.
- Raw source snapshots are omitted by default and require the `admin` role plus
  `include_raw=true`.
- Real OpenCTI export is disabled unless
  `NARROWCTI_REVIEW_API_ALLOW_EXPORT=true` is explicit.
- Interactive API documentation is disabled by default.
- HTTP Host values are allow-listed and declared request bodies are bounded.

The file-backed review service runs as one API process. Do not scale it
horizontally until the quarantine and audit repositories use a transactional
shared backend.

## Roles

| Role | Permissions |
| --- | --- |
| `reader` | Queue summary, record list/detail and audit reads. |
| `reviewer` | Reader access, release, partial release, reject and export preview. |
| `exporter` | Reader access, export preview and explicitly enabled real export. |
| `admin` | All permissions, including explicit raw snapshot access. |

Roles are intentionally separate. A principal that both decides and exports
must receive both roles or `admin`.

## Create Credentials

Generate a random token and its hash:

```powershell
python -m gateway.review_auth
```

The command prints the raw token once and its SHA-256 hash. Store the raw token
in the caller's secret manager. Put only the hash in a local credential file:

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
ignored by Git and Docker build context.

## Start With Compose

Keep runtime values in the local deployment env file:

```text
NARROWCTI_REVIEW_API_DOCS_ENABLED=false
NARROWCTI_REVIEW_API_ALLOW_EXPORT=false
NARROWCTI_REVIEW_API_ALLOWED_HOSTS=127.0.0.1,localhost
NARROWCTI_REVIEW_API_MAX_BODY_BYTES=16384
```

The credential source and published port are Compose host interpolations. Set
them in the shell that starts Compose:

```powershell
$env:NARROWCTI_REVIEW_API_CREDENTIALS_SOURCE = "./review-api-credentials.json"
$env:NARROWCTI_REVIEW_API_PUBLISHED_PORT = "8081"
```

Start the isolated profile:

```powershell
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile review-api up -d --build narrowcti-review-api
docker compose -f deployment\docker-compose.narrowcti-gateway.yml --profile review-api ps
```

The host endpoint is `http://127.0.0.1:8081`. Put the service behind an
authenticated TLS reverse proxy before remote access; do not publish the
container port broadly on an untrusted network.

## HTTP Surface

| Method | Path | Required permission |
| --- | --- | --- |
| `GET` | `/healthz` | Public liveness only. |
| `GET` | `/api/v1/review/summary` | `review:read` |
| `GET` | `/api/v1/review/records` | `review:read` |
| `GET` | `/api/v1/review/records/{id}` | `review:read` |
| `GET` | `/api/v1/review/audit` | `review:read` |
| `POST` | `/api/v1/review/records/{id}/release` | `review:decide` |
| `POST` | `/api/v1/review/records/{id}/release-indicators` | `review:decide` |
| `POST` | `/api/v1/review/records/{id}/reject` | `review:decide` |
| `POST` | `/api/v1/review/records/{id}/export-preview` | `export:preview` |
| `POST` | `/api/v1/review/records/{id}/export` | `export:execute` and export enabled |

Example decision:

```powershell
$headers = @{ Authorization = "Bearer $env:NARROWCTI_REVIEW_TOKEN" }
$body = @{ reason = "Relevant to monitored scope" } | ConvertTo-Json
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8081/api/v1/review/records/<id>/release" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body $body
```

Partial release uses a JSON `indicator_types` list. Real export should be
enabled only after preview, deduplication and OpenCTI capacity checks pass.

## Audit Behavior

Release, partial release, reject and export transitions continue to append to
`NARROWCTI_RELEASE_AUDIT_FILE`. Real API exports identify the executor as
`review-api:<authenticated principal>`. The API never accepts caller-supplied
reviewer or exporter identities.

## DAST

`.github/workflows/dast.yml` builds a disposable API image and state directory,
creates a temporary masked credential, verifies `401` and authenticated `200`
behavior, then runs the pinned OWASP ZAP `2.17.0` OpenAPI scan. The workflow
uploads JSON, HTML and Markdown evidence and removes its container and network
even when the scan fails.
