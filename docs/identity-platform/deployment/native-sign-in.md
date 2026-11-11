# Native sign-in and environment registration

Status: draft provider contract for Dutch and Host review, 2026-11-09. Task `iam/DEP-7`.
This is the IAM side of the native sign-in lane; Dutch owns the device exchange and the Host owns
deep-link dispatch.

## Boundary

| Party | Owns |
|---|---|
| IAM | App registration, authorization and token endpoints, PKCE/DPoP validation, issuer and discovery, signing keys, rate limits and replay |
| Dutch | Device DPoP key, external-browser authorization, code exchange, session/refresh handling, sign-out wipe, stale-credential refusal |
| Host | Deep-link dispatch only; never holds product credentials or performs the exchange |

## Environment registration

One app registration per environment. The registration is a reviewed manifest reconciled into the
pinned allowlist; there is no runtime self-registration.

| Field | Development | Staging / production |
|---|---|---|
| `appRegistrationId` | `dutch-development` | to be assigned |
| `clientId` | `dutch-mobile` | to be assigned |
| Client type | `NATIVE_PUBLIC` | `NATIVE_PUBLIC` |
| Browser mode | `EXTERNAL` | `EXTERNAL` |
| Redirect | `dutch://oauth/callback` | custom scheme or HTTPS app link — **open** |
| Grant | `authorization_code` | `authorization_code` |
| PKCE | `S256` | `S256` |
| Resource audience | `https://api.dutch.invalid` | Dutch API audience — **open** |
| Scopes | `member:read` | Dutch API scopes — **open** |
| DPoP required | yes | yes |
| Issuer | development issuer | `portfolio/INFRA-13` binding |

The issuer is infra-provided and must be HTTPS, path-free, stable per environment, and pinned once.
A new environment is a new registration and issuer, never a shared one.

## Authorization request

- `response_type=code`, one registered `client_id`, exact registered `redirect_uri`.
- `code_challenge` with `S256`; no `plain`.
- `state` and `nonce` are required opaque bounded values and are echoed/validated.
- Exactly one resource audience; every requested scope is in the registration.
- No client secret, no embedded webview, no refresh on the authorization request.

## Token and proof

- The token request carries exactly one DPoP proof with `htm=POST`, the exact token endpoint URI,
  `iat`, a unique `jti`, and the server nonce when challenged.
- The issued access token is `human_access` v1 with `cnf.jkt` equal to the proof key thumbprint.
- The token endpoint rejects a missing, malformed, replayed, wrong-target or wrong-nonce proof and a
  wrong client/app/audience; no ID token is returned. A refresh token is returned only when the
  native refresh grant is enabled.
- Resource requests repeat the DPoP proof with `ath` bound to the access token.
- Replay state, nonce issuance and rate limits are durable and fail closed.

## Refresh (accepted 2026-11-09)

DPoP-bound rotating refresh. A refresh token is opaque, single-use, bound to the device DPoP key and
belongs to a family scoped to one human identity, app registration, client and device.

- Every use rotates the token; presenting a used or superseded generation revokes the family.
- Families carry a 30-day absolute lifetime, a 7-day idle timeout, a maximum generation and a
  security-version binding (accepted 2026-11-09).
- Access tokens remain at most 15 minutes and are bound to the same DPoP key; the response contains
  no ID token.
- Refresh tokens are stored only as digests and are never accepted as bearer credentials.
- Identity disable/delete, reuse detection, operator action or a client revoke ends the family.

**Refresh request.** `grant_type=refresh_token`, the opaque `refresh_token`, `client_id`, and one
DPoP proof for the token endpoint. No `redirect_uri`, `code` or `code_verifier`.

**Refresh response.** The normal DPoP token response plus the rotated `refresh_token`; no ID token.
A reused or superseded refresh token returns `invalid_grant` and revokes the family. Wrong device key,
security-version advance, registration change, revocation and expiry also end the family.

Decision: `capabilities/work/decisions/iam-native-refresh-001.yaml`.

## Account lifecycle

- Activation requires the registered evidence: verified identifier, usable factor, recovery path.
- An active app registration does not imply a ready profile; UMS owns `PROFILE_REQUIRED` →
  `PROFILE_READY`. The native client must render both states honestly.
- Invite-cohort accounts use the same activation path; no synthetic bypass in staging evidence.

## Keys and limits

- Signing key: IAM access-token key, custody via DEP-4; published in the platform JWKS.
- Device key: generated and held by Dutch; the proof JWK is public only.
- Limits: authorization and token endpoint rate limits, DPoP nonce/replay caches, and bounded request
  bodies. No credential, proof or token value enters logs or metrics.

## Proof plan

Local, before the real issuer:

1. Register the development manifest and enable authorization, token and DPoP in the local runtime
   with a test signing capability.
2. Drive authorization → code → DPoP token → resource read with a real authenticated principal.
3. Reject wrong app, audience, key, replay, missing proof, wrong nonce and a stale security version.

Staging, after `portfolio/INFRA-13` and DEP-4:

4. Repeat against the real issuer and TLS with a staging registration.
5. Dutch records device-side evidence; the Host records deep-link dispatch and no-credential proof.

## Open decisions

1. Staging/production redirect: custom scheme or HTTPS app link.
2. Dutch API audience and scope set.
3. Staging/production registration IDs and approver.
4. Issuer hostnames and certificate binding (`portfolio/INFRA-13`).
5. Whether a client-initiated `/oauth2/revoke` endpoint ships with the first slice.
6. Confirm the 30-day absolute and 7-day idle refresh lifetimes.
