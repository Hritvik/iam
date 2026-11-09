# Workload access token profile v1

Status: **accepted 2026-11-08 by the portfolio owner** and published as `workload_access` v1.
The token is an accepted alternative to mTLS on the onboarding snapshot and the credential IAM's
outbox relay presents to a consumer. mTLS remains published and unchanged.

## Profile at a glance

| Element | Value |
|---|---|
| JOSE header | `typ=at+jwt`, `alg=ES256`, `kid` |
| Issuer | the IAM issuer (`iss`) |
| Token profile | `workload_access` |
| Token version | `1` |
| Subject kind | `workload` |
| Subject | `wl_` + 22–128 base64url characters |
| Audience | exactly one registered workload audience |
| Lifetime | 60–900 seconds |
| Confirmation key | none — workload tokens are not DPoP-bound |
| Delegation | none — no `act`, no token exchange |
| Signing key | the workload ES256 key, published in the IAM platform JWKS |
| Trust bundle | `https://<iam-issuer>/oauth2/jwks` (the platform JWKS) |

## Claims

Exactly these claims are allowed. An undeclared claim, a duplicate claim, or a missing claim is
rejected.

| Claim | Type | Rule |
|---|---|---|
| `iss` | string | equals the configured IAM issuer, HTTPS |
| `sub` | string | `wl_` workload identity; never a human identity or app subject |
| `aud` | string | exactly one registered workload audience |
| `iat` | integer | issue time, epoch seconds |
| `exp` | integer | `exp > iat`, lifetime at most 900 seconds |
| `jti` | string | 16–128 base64url characters, unique per token |
| `client_id` | string | the registered workload client |
| `token_profile` | string | `workload_access` |
| `token_version` | integer | `1` |
| `subject_kind` | string | `workload` |
| `scope` | string | space-separated, sorted, unique, each matching `^[a-z][a-z0-9:_-]{0,63}$` |
| `app_id` | string | the owning app registration |
| `security_version` | integer | the binding's registered authority version; a resource rejects a mismatch |

A workload token is invalid if it carries `cnf`, `acr`, `amr`, `auth_time`, `act`, a human subject,
or any other claim.

## Registration binding

A token is accepted only when all of the following match one registered binding:

| Binding field | Must equal |
|---|---|
| `workloadId` | `sub` |
| `appRegistrationId` | `app_id` |
| `clientId` | `client_id` |
| `audiences` | contains `aud` |
| `scopes` | contains every scope in `scope` |

The resource's required audience and scope are additional checks. A mismatch returns the resource's
non-enumerating 404; it never reveals which side was wrong.

## Key custody and rotation

- The workload signing key is an ES256 (P-256) key held through the platform's key custody path.
  Its public half is served from the platform JWKS at `/oauth2/jwks`, alongside any human
  access-token keys. IAM signs every token; a registration holds only public binding metadata.
  Workload-held keys become relevant only if a later `private_key_jwt` endpoint is accepted; this
  profile does not require one.
- The active key signs; published keys remain in the JWKS until every token they signed has expired.
  Because the lifetime is at most 15 minutes, rotation needs only a short overlap. A new `kid` is
  published alongside the old one before signing switches.
- A compromised key is removed from the JWKS, which invalidates new verification immediately for any
  token signed by it; existing tokens are short-lived by design.
- `kid` selection is exact. A token with an unknown `kid` is rejected even if another published key
  would verify it.

## Resource acceptance

A resource that accepts this profile must point its JWKS trust at `https://<iam-issuer>/oauth2/jwks`.
It must:

1. Read exactly one `Authorization: Bearer` header.
2. Verify the ES256 signature with the key selected by `kid` from the IAM JWKS.
3. Enforce the exact header and claim set above.
4. Enforce `iss`, a single `aud`, and the registered binding.
5. Enforce `exp > iat`, the 900-second ceiling, and a bounded clock skew (≤ 60 seconds).
6. Enforce that `scope` contains the route's required scope and is a subset of the binding.
7. Reject replay or duplicate `jti` where the route mutates state.
8. Answer a wrong app, scope, audience, or unregistered workload with a non-enumerating 404.
9. Never log the token, the raw claims, or personal data from the request.

## Onboarding snapshot

`GET /internal/v1/apps/{appRegistrationId}/onboarding` accepts either. Both are accepted; neither
replaces the other:

- `registeredWorkloadMtls` — the existing mutual-TLS scheme, unchanged; or
- `registeredWorkloadToken` — this profile.

The token route requires `aud=https://iam.distracted.invalid/internal/onboarding` and
`scope=iam:onboarding:read`, and the path app must equal `app_id`.

## Outbound event delivery

IAM's relay presents this profile to the consumer's ingestion endpoint (`POST https://ums.example.test/internal/v1/iam/events`):

| Field | Development value |
|---|---|
| `app_id` | `dutch-development` |
| `client_id` | `iam-relay` |
| `aud` | `https://ums.example.test/internal/iam/events` |
| `scope` | `ums:onboarding:write` |
| `security_version` | the registered binding version (1) |

The consumer must accept `workload_access` v1 alongside `human_access` v1. It must not treat a
workload token as a human caller: no user subject, no recent-authentication assurance, and no
profile readiness follow from it.

The relay mints a **fresh token for every delivery attempt**, so each mutating request carries a new
`jti`. The event id remains the idempotency key across retries; the credential does not. A consumer
may therefore reject a repeated `jti` on a mutating route without breaking legitimate retries.

## Deliberate limits

- **No general client-credentials endpoint.** Tokens are issued by IAM's runtime for registered
  bindings; IAM does not expose a public workload token endpoint. The human `/oauth2/token` surface
  is unchanged and still rejects bearer client-credentials grants.
- **No delegation.** `act` and token exchange are out of scope; a workload acts only for itself and
  its owning app registration.
- **No refresh tokens.** IAM mints a new short-lived token for each delivery attempt.
- **Registrations are configuration for now.** Reviewed workload manifests are the production path;
  until that exists, bindings are injected from secret-backed configuration and reviewed with the
  deployment.
