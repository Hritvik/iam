# Run IAM locally

This is the DEP-1 runtime: the executable jar, PostgreSQL, Flyway migrations, actuator health probes,
secret-backed cryptographic capabilities, and the pinned Dutch development app registration.
Identity fixtures stay off: the deterministic fixture runner is a test surface, not part of this runtime.

It is a **development** environment only. It uses locally generated key material. The listener serves
HTTP and advertises `https://iam.localhost` as its issuer. Real issuer, TLS, key custody, outbox
transport and workload identity arrive in DEP-2…DEP-4.

## Prerequisites

- Docker with Compose v2
- `openssl` (only to generate local credentials)

The build runs inside the container; no local JDK is required.

## 1. Generate local credentials

```bash
./deploy/generate-local-secrets.sh
```

This writes a chmod-600 `.env` with random PostgreSQL credentials and four independent key materials:

| Variable prefix | Purpose |
|---|---|
| `IAM_MIGRATOR_PASSWORD` | Flyway migration role |
| `IAM_RUNTIME_PASSWORD` | Application runtime role |
| `IAM_RELAY_PASSWORD` | Reserved for the DEP-2 relay role |
| `IAM_REGISTRATION_RECONCILER_PASSWORD` | Pinned-registration reconciler role |
| `IAM_CRYPTO_LOCAL_SIGNER_PRIVATE_KEY` | ES256 (P-256) PKCS#8 signing key |
| `IAM_CRYPTO_LOCAL_ENCRYPTION_KEY` | AES-256-GCM identifier encryption key |
| `IAM_CRYPTO_LOCAL_BLIND_INDEX_KEY` | HMAC-SHA-256 identifier blind-index key |
| `IAM_CRYPTO_LOCAL_CHALLENGE_DIGEST_KEY` | HMAC-SHA-256 verification-challenge digest key |

`.env` is git-ignored. Every run of the generator creates a new, disposable set. Do not reuse these
values outside local development. Compose passes IAM an explicit set of application credentials.
PostgreSQL bootstrap and relay credentials stay out of the IAM container.

## 2. Start the service

```bash
docker compose up --build --detach
docker compose ps
```

On first start PostgreSQL provisions the four IAM roles, then Flyway runs as `iam_migrator` while the
application connects as `iam_runtime`. The application fails to start if any role, migration, secret
or capability is missing; there is no fallback path. The IAM listener is published on IPv4 loopback.
Use `docker compose exec postgres` for local database inspection.

## 3. Prove it is running

```bash
curl --fail --silent --show-error http://localhost:8080/actuator/health/readiness
curl --fail --silent --show-error http://localhost:8080/actuator/health/liveness
```

Both probes are public and report status only. Details stay hidden, and every other actuator endpoint
remains behind the deny-all foundation chain.

On a disposable stack, stop PostgreSQL with `docker compose stop postgres`. Readiness returns
HTTP 503 while liveness returns HTTP 200. Start PostgreSQL again with
`docker compose start --wait postgres` and wait for readiness to return HTTP 200.

The pinned registration is reconciled at startup and exposed through discovery:

```bash
curl --silent http://localhost:8080/.well-known/oauth-authorization-server
curl --silent http://localhost:8080/.well-known/oauth-protected-resource
```

The startup log records the reconciliation:

```bash
docker compose logs iam | grep "Pinned registration"
```

## 4. Inspect the database

```bash
docker compose exec postgres psql -U postgres -d iam -c "select app_registration_id, environment from app_registration;"
docker compose exec postgres psql -U postgres -d iam -c "select version, success from flyway_schema_history order by installed_rank;"
docker compose exec postgres psql -U postgres -d iam -c "select rolname from pg_roles where rolname like 'iam%' order by rolname;"
```

Expected: a `dutch-development` registration, every migration successful, and the four IAM roles.

## 5. Stop and reset

```bash
docker compose down          # keep the database volume
docker compose down --volumes  # discard database data and role state
```

## What this does not prove

- **No production capabilities.** The local keyring is bound to `development` and excluded whenever
  a production-like profile is active. DEP-4 supplies real key custody and issuer signing. The local
  startup capability alone does not serve JWKS.
- **No outbox delivery.** The relay schema exists, but DEP-2 owns the transport and scheduler.
- **No identity fixture data.** The deterministic fixture runner only activates for tests, so this
  runtime proves packaging and registration, not the identity flows.
- **No workload identity.** DEP-3 owns snapshot authentication.
- **No TLS or real issuer.** The issuer is `https://iam.localhost`; DEP-4 owns DNS, TLS and rotation.
- **No production operations.** DEP-6 owns backups, alerts, SLOs and release approval.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `required IAM privilege roles are not provisioned` | PostgreSQL volume was created before the init script; reset with `docker compose down --volumes`. |
| `local_crypto_configuration_missing` | `.env` was not generated, or a key variable is empty. |
| `registration_reconciler_configuration_missing` | Reconciler URL, user or password is empty. |
| `registration_authority_invalid` | Runtime and reconciler roles share a credential or membership. |
| Readiness probe fails while liveness passes | Database connectivity or a failed migration. |

## Workload identity and the relay

The development runtime also wires the workload profile from secret-backed keys:

- `IAM_WORKLOAD_ENABLED=true` creates the workload issuer and verifier.
- `IAM_MESSAGING_ENABLED=true` exposes the internal onboarding snapshot route.
- `IAM_RELAY_ENABLED=false` keeps outbound delivery off until a consumer endpoint exists.

Verify the snapshot fails closed without a token:

```bash
docker compose exec iam curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:8080/internal/v1/apps/dutch-development/onboarding
```

It must print `404`, both anonymously and with a malformed bearer token. The route never reveals
whether the app, audience, scope, or workload was wrong.

To exercise outbound delivery, provide a consumer endpoint and enable the relay:

```bash
# in .env
IAM_RELAY_ENABLED=true
IAM_RELAY_ENDPOINT=https://ums.localhost/internal/v1/iam/events
IAM_RELAY_SCHEDULE_ENABLED=true
IAM_WORKLOAD_AUDIENCE=https://ums.localhost/internal/v1/iam/events
IAM_WORKLOAD_SCOPE=ums:onboarding:write
```

The relay mints a short-lived workload token, posts the published event envelope, acknowledges on
2xx, retries 408/429/5xx, and quarantines other 4xx. Counters appear as
`iam.relay.deliveries{outcome=claimed|published|acknowledged|quarantined}`.

The full profile is in [workload-token-profile.md](workload-token-profile.md).
