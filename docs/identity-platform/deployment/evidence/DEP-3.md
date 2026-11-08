# DEP-3 evidence — workload identity for the snapshot

Date: 2026-11-08
Environment: local development runtime, PostgreSQL 18, Docker Compose
Profile: `development`

## Published profile

| Artifact | Path |
|---|---|
| Workload token header schema | `contracts/oauth/workload-access-token-header.schema.json` |
| Workload token claims schema | `contracts/oauth/workload-access-token-claims.schema.json` |
| Conformance requirements | `contracts/conformance/semantic-requirements.yaml` (`token.workloadAccess`) |
| Published profile | `docs/identity-platform/deployment/workload-token-profile.md` |
| Snapshot contract | `contracts/http/iam-onboarding-snapshot.openapi.yaml` — `registeredWorkloadToken` added as an alternative to `registeredWorkloadMtls` |

The profile fixes the issuer, exact claim set, one audience, the registered app/client/workload
binding, scopes, the 60–900 second lifetime, the ES256 key set, and the trust bundle at the IAM JWKS.

## Implementation

- `WorkloadAccessTokenIssuer` mints `workload_access` v1 tokens for a registered binding.
- `WorkloadAccessTokenVerifier` enforces the signature, exact header and claim set, issuer,
  audience, binding, scopes, `iat`/`exp`, skew and `jti`.
- `JwtWorkloadAuthenticator` turns a valid `Authorization: Bearer` token into the workload principal
  used by the internal snapshot route; every failure is an empty principal.
- `WorkloadIdentityConfiguration` wires issuance and verification when `iam.workload.enabled=true`.

## Runtime check

```bash
docker compose up --build --detach
docker compose exec iam curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:8080/internal/v1/apps/dutch-development/onboarding
docker compose exec iam curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Authorization: Bearer not.a.token' \
  http://localhost:8080/internal/v1/apps/dutch-development/onboarding
```

Observed: `404` and `404`. The route is wired and fails closed without a valid workload token.

Also observed with the runtime still healthy:

- `GET /actuator/health/readiness` → `{"status":"UP"}`
- `GET /.well-known/oauth-protected-resource` → the Dutch resource metadata
- `Pinned registration created; appRegistrationId=dutch-development`
- No relay activity, because `IAM_RELAY_ENABLED=false`

## Tests

```text
unit tests         406 passed
integration tests  319 passed
contract tests       8 passed
```

Focused coverage:

- Issue-and-verify round trip with the registered workload.
- Rejection of wrong audience, wrong required scope, foreign app binding, unregistered workload,
  wrong issuer, expired token, tampered signature, malformed compact, wrong header `typ`, unknown
  `kid`, human profile claims, duplicate/unsorted/oversized scope, non-canonical subject, invalid
  app/client, zero security version, future `iat`, over-long and expired `exp`.
- Authenticator rejection of missing, non-bearer, empty, malformed and non-HTTP requests.
- Issuer rejection of invalid issuer forms, lifetimes, key material, key ids and binding shapes.
- Contract validation of the new schemas and valid/invalid fixtures.

## Bundle publication

```text
contracts/catalog.yaml version   1.1.0
iam-contracts-1.1.0.zip          build/distributions/
sha256                           f54829318161688314e26c4feb3f0f10faeaab9669926393cf769028dbbd74ff
```

The bundle adds the workload token header and claims schemas, the conformance block, and the
additive snapshot security alternative. It is reproducible with `./gradlew contractBundle`.

The central pin at `portfolio-planning/contracts/http/iam.onboarding-snapshot.v1/v1/openapi.yaml`
still shows mTLS only. Refreshing that copy and its registry hash needs an IAM commit first, because
the registry records the provider commit that contains the artifact. The provider bundle above is
ready; the pin refresh is the handoff step.

## Deliberate gaps

- **No general workload token endpoint.** Tokens are minted inside IAM for registered bindings; the
  human `/oauth2/token` surface is unchanged.
- **UMS cannot yet obtain a token for the snapshot pull.** The accepted decision uses the token for
  IAM-to-UMS delivery; the pull path retains mTLS, which needs DEP-4's TLS listener and certificate
  custody. A token-based pull would need a separate issuance decision (for example a narrow
  `private_key_jwt` endpoint). This is tracked with `ums/IAM-RUNTIME-INGRESS`.
- **Registrations are configuration.** The reviewed workload manifest path is a later change; runtime
  bindings are injected from secret-backed configuration.
- **mTLS remains.** The OpenAPI lists both mechanisms; the token alternative is additive. The
  portfolio owner accepted the token for delivery on 2026-11-08; UMS still has to implement
  acceptance on its ingestion route.
- **No replay store.** The snapshot route is read-only, so duplicate `jti` does not mutate state; a
  mutating workload route will need a replay cache.
