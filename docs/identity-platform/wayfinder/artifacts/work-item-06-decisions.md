# W-6 implementation decisions — closed signed human access token

Status: implementation-ready preflight  
Work item: [W-6 — Issue the closed signed human access token](../work-items.md#w-6--issue-the-closed-signed-human-access-token)  
Depends on: accepted W-4 consumed-authorization port, accepted W-5 App Subject resolver, and the published OAuth/JWKS contracts  
Runtime baseline: Java 25, Spring Boot 4.1.1, Spring Authorization Server 7.1.1

## Scope and stop line

W-6 implements the closed human access-token model, an ES256 signing capability, verification of the produced JWT, and public JWKS publication. It produces a signed RFC 9068-style `at+jwt` only from a trusted, already-consumed authorization tuple, a resolved App Subject, current IAM security state, and a required DPoP public-key thumbprint. It never accepts a free-form claim map.

W-6 does **not** open `/oauth2/token`, consume an authorization code, validate a DPoP proof, persist DPoP replay/nonce state, activate an app, publish onboarding, or issue a refresh/ID token. W-7 owns the official Spring Authorization Server token provider and the transaction/workflow that composes W-4 redemption, W-5 subject resolution, current-security-state resolution, DPoP validation, and this signer. This separation is deliberate: W-6 must not create a token endpoint that can issue a bearer native token or consume a code before the sender-constrained workflow is complete.

No OAuth, JWT, private-key, or issuance record is added to PostgreSQL in W-6. Access tokens remain self-contained short-lived credentials; private key state belongs to the external signing capability, not the service database. W-7 must record any allowlisted issuance audit in the same workflow as code consumption. W-6 emits no outbox event.

Review correction: V8 adds one read-only `SECURITY DEFINER` function over the existing V6
`authorization_server_issuer` singleton. It creates no new authority or token state. `iam_runtime` may execute the
fixed-search-path reader but retains no table access; PUBLIC and unrelated roles cannot execute it. The issuer
compares configured issuer text with this migration-owned value and rejects missing, duplicate, drifted, or
unavailable authority.

The existing published contracts are authoritative and require no additive contract change.

## Trusted issuance boundary

Add immutable authorization-module types:

- `HumanAccessTokenIssuer.issue(HumanAccessTokenIssueCommand)` returns `SignedHumanAccessToken`.
- `HumanAccessTokenIssueCommand` contains only `ConsumedAuthorization`, resolved `AppSubject`, a positive current `securityVersion`, a validated `DpopKeyThumbprint`, and an internal issuance correlation ID. It does not accept issuer, audience, app, client, scope, subject kind, profile, version, times, algorithm, key ID, or arbitrary claims from an HTTP request.
- `DpopKeyThumbprint` accepts exactly 43 canonical unpadded base64url characters representing 32 bytes. W-6 treats it as a trusted binding value; only W-7 may construct it from a successfully validated proof.
- `SignedHumanAccessToken` exposes the compact JWT only to the future token response adapter and has a redacted `toString()`. It has no JSON/debug serialization surface.
- `AccessTokenMaterialGenerator` generates a 128-bit-or-greater opaque `jti`; production uses `SecureRandom`, tests inject deterministic material.

The issuer uses the W-3 canonical `RegistrationRegistry` to re-resolve `ConsumedAuthorization.appRegistrationId` and rejects unless issuer, app, client, scalar resource audience, and canonical sorted scope remain an exact coherent registered tuple and the policy still requires DPoP. It rejects unless the supplied App Subject is valid and belongs to the same app/identity through a narrow IAM-internal context port. That port may be implemented by a parameterized, read-only security-definer database function in W-7 when the complete issuance transaction is introduced; W-6 tests use a trusted in-memory port. W-6 must not add direct runtime table reads or broaden W-5's no-enumeration surface.

The command's `securityVersion` is never caller-selected at an HTTP boundary. It represents the positive current `human_identity.security_version` returned by the future transaction authority. W-6 validates and copies it into the token; W-7 must resolve it while confirming that the identity remains active. A stale or mismatched context is rejected before signing.

This arrangement makes the W-6 issuer testable without pretending that token-endpoint atomicity is solved. W-7 must not expose `HumanAccessTokenIssueCommand` as request binding and must not use a pre-consumption lookup seam.

## Closed JOSE header and claim profile

The JOSE protected header is exactly:

```json
{"typ":"at+jwt","alg":"ES256","kid":"<active signing key id>"}
```

No `jwk`, `jku`, `x5u`, `x5c`, `crit`, compression, unprotected header, symmetric algorithm, `none`, algorithm negotiation, or caller-supplied header is permitted. `kid` is 8–128 URL-safe characters and must identify the active public key in the simultaneously published JWKS.

The payload is exactly the published required set:

| Claim | Authority |
|---|---|
| `iss` | validated configured issuer; must equal the migration-pinned/W-3 issuer |
| `sub` | resolved opaque App Subject |
| `aud` | scalar canonical registered resource audience |
| `iat` | issuer clock, whole NumericDate seconds |
| `exp` | `iat + configured lifetime` |
| `jti` | fresh CSPRNG-backed opaque identifier |
| `client_id` | consumed canonical registration tuple |
| `token_profile` | literal `human_access` |
| `token_version` | integer `1` |
| `subject_kind` | literal `app_subject` |
| `scope` | sorted, single-space canonical consumed registered subset |
| `app_id` | consumed canonical app registration ID |
| `security_version` | current positive IAM identity security version from the trusted context |
| `cnf` | object containing only `jkt`, the validated DPoP thumbprint |

`aud` is always one JSON string, never an array. The token has no email, phone, identifier, Human Identity ID, authorization/code/request ID, redirect, state, nonce, credential/factor detail, profile/member ID, role/permission, product data, correlation ID, environment, free-form metadata, or arbitrary claim.

The optional `acr`, `amr`, and `auth_time` claims are absent in W-6. W-4 does not yet persist an authenticated assurance context, so inventing these values would be false. A later additive change may include them only from a trusted authentication result and only with contract tests preserving the closed allowlist.

Use a configurable lifetime with a default of 300 seconds and an accepted range of 60–900 seconds. The injected clock is sampled once per issuance, truncated to whole seconds; `exp` must be strictly greater than `iat`. Clock rollback, overflow, invalid duration, or non-positive NumericDate fails closed. Validators use a separately bounded clock-skew configuration (default 30 seconds, range 0–60) only when verifying, never to extend the encoded expiry.

## Signing capability and configuration

Replace the underspecified byte-only marker with a purpose-specific `AccessTokenSigningCapability` port. Its closed surface is:

- metadata fixed to purpose `ACCESS_TOKEN_SIGNING`, algorithm `ES256`, and one active `kid`/key reference;
- `sign(protectedHeaderBytes, payloadBytes)` or an equivalent structured operation that cannot substitute headers/claims;
- `publicJwks()` returning only immutable public verification keys; and
- `selfCheck()` proving the active private signer and advertised public key form a working ES256 pair.

The adapter must use P-256 ECDSA with SHA-256 and JOSE's 64-byte `R || S` signature encoding. It rejects malformed/non-canonical signatures and verifies every produced token with the matching public key before returning it. Prefer the Spring Security/Nimbus JOSE implementation already supplied by the authorization-server dependency rather than hand-building ASN.1/JOSE conversion.

Review correction: the provider exposes one immutable signing snapshot containing purpose, algorithm, active
`kid`, public keys, health result, and a signing operation already bound to that active key. Publication and one
issuer instance capture exactly one snapshot and never re-read mutable provider metadata. Self-check, JWKS output,
protected header, signing, and produced-token verification all use that same snapshot.

Production-like profiles require an explicitly supplied external capability bean and an explicit `iam.token.enabled=true`. Startup fails if the capability is absent, unhealthy, wrong-purpose, non-ES256, missing its active public key, has duplicate/invalid key IDs, advertises private JWK parameters, or fails a sign/verify self-check. There is no generated production key, classpath private key, default password, environment-variable private PEM fallback, unsigned token, HMAC fallback, or reuse of identifier/challenge/code keys.

Development/test may install a clearly test-scoped capability only under test or the isolated development fixture safety gate. Tests may generate an ephemeral in-memory P-256 key inside the test process or load explicitly non-production test material; neither path is a normal/production bean and neither commits a secret. Enabling the deterministic identity fixture does not itself enable signing.

The capability is provider-neutral. Cloud KMS/HSM/vendor selection, credentials, key creation, and rotation automation are deployment concerns and remain outside this repository decision.

## JWKS publication and rotation

When W-6 is explicitly enabled and the signing capability is healthy, expose unauthenticated `GET` and `HEAD /oauth2/jwks`. All other methods fail. The response validates against `contracts/oauth/jwks.schema.json` and is exactly `{"keys":[...]}` with 1–8 keys. Every key contains only `kty=EC`, `use=sig`, `alg=ES256`, `kid`, `crv=P-256`, `x`, and `y`. Private `d`, certificate chains, provider/key references, status, timestamps, or arbitrary JWK members are forbidden.

Keys are sorted lexically by `kid` for stable serialization. The active signing key is present exactly once. Verification-only retiring keys may remain, but the signer never chooses one for new tokens. Duplicate key IDs or two different public keys under one ID fail startup. The endpoint returns `application/json`, `Cache-Control: public, max-age=300, must-revalidate`, a strong ETag over canonical public JSON, and `X-Content-Type-Options: nosniff`; it returns no cookies and has no request-dependent body. `HEAD` has GET-equivalent status/cache/ETag headers and no body. Conditional `If-None-Match` may return `304` with the same cache policy.

Rotation is externally supplied as one active signing key plus retained public verification keys. The old public key must remain advertised for at least the maximum access-token lifetime plus maximum verifier skew after its last token was signed. Tests exercise active-key change, overlap, removal only after the acceptance window, restart stability, and a stale-cache verifier. W-6 does not persist keys, accept a JWKS URL, fetch remote keys, or publish an unhealthy/empty set.

The existing authorization-server metadata already names `/oauth2/jwks`; W-6 makes that URI operational without changing advertised grant types. `/oauth2/token` remains deny-all until W-7.

## Token validation and safe failures

Add a strict internal `HumanAccessTokenVerifier` used by tests and future resource adapters. It must independently reject wrong/missing/duplicate header members, `typ`, `alg`, `kid`, curve/key/use, signature, issuer, scalar audience, app/client tuple, subject shape, token/profile/subject version literals, scope grammar/membership/order, `security_version`, `cnf.jkt`, `iat`, `exp`, `jti`, and any undeclared claim/header. It selects a verification key by exact `kid` and pins ES256 before signature verification; it never trusts the token's algorithm to select a broader verifier.

Externally visible issuance failures eventually map at W-7 to standard correlated OAuth errors. W-6 uses closed internal reasons (`invalid_context`, `signer_unavailable`, `signing_failed`) and fixed safe messages. It never includes a token, signing input/signature, claims, subject, thumbprint, key material/reference, provider error, identity ID, SQL detail, or stack trace in an error. A signer failure returns no partial token.

No compact token is logged, metric-labeled, traced, stored in audit/outbox/database, or included in a normal API/debug response. Metrics use bounded outcomes and active-key generation/version categories that reveal neither `kid` nor provider reference. Access logging must redact any future token response body; W-6 itself has no such endpoint.

## TDD acceptance matrix

Record one observed behavioral RED before each production increment and the exact GREEN/refactor command. A compilation failure or already-green test is not behavioral RED.

### Unit and property tests

1. Header is exactly `typ`, `alg`, `kid`; payload is exactly the required closed set. Literal unknown headers/claims, `none`, HS/RS algorithms, JWK injection, multi-audience, wrong constant/version/kind, and arbitrary data are rejected.
2. App/client/audience/scope/issuer are rederived from the canonical registration and cannot be overridden by the command. `sub` is the supplied app-scoped subject; global identity and every PII/credential/profile canary are absent.
3. `jti` has at least 128 bits of CSPRNG material and is unique under the deterministic/property matrix. Time tests cover one clock sample, second truncation, expiry, duration/skew bounds, overflow, future `iat`, expired/not-yet-valid values, and exact boundaries.
4. `cnf.jkt` is mandatory, canonical, and exactly 32 bytes. There is no bearer-token branch. Optional `acr`/`amr`/`auth_time` are absent.
5. ES256 output verifies with the advertised active key. Wrong key, key ID, curve, algorithm, type, signature encoding, altered header/payload/signature, and missing/duplicate key fail closed.
6. Domain objects are immutable and render safely; compact tokens and signer/key material never appear in `toString()`, exceptions, serialization diagnostics, logs, metric tags, or traces.
7. Architecture rules keep JOSE/web adapters out of domain/application records, prohibit free-form claim maps, and prove W-6 adds no code consumption, DPoP proof validation, refresh/ID token, activation, outbox, or token endpoint.

### JWKS and HTTP tests

1. Healthy explicit capability yields contract-valid sorted JWKS with the active key and allowed retained public keys only. GET/HEAD, ETag/304, cache headers, media type, no cookies, and no private/provider fields are exact.
2. Empty, malformed, duplicate-ID, private-member, mismatched active-key, wrong-purpose/algorithm/curve, or self-check-failing capability prevents W-6 startup or yields the fixed correlated `503 temporarily_unavailable` without publishing partial material.
3. Production-like startup with W-6 enabled and no external capability fails. Disabled W-6 leaves JWKS and token endpoint denied. Test/development capability wiring is absent from normal and production contexts.
4. Rotation publishes old+new during overlap, signs only with the new active key, validates both generations, preserves the set after a full context restart, and removes the old public key only after its acceptance window. Cached-old and refreshed-JWKS verifier cases are covered.
5. `/oauth2/token`, OIDC discovery, UserInfo, introspection, revocation, device, and dynamic-registration endpoints remain denied; metadata still advertises only authorization code and S256 and never refresh.

### Privacy, contracts, and verification

1. Canary-scan compact-token-adjacent results, response bodies/headers, errors, structured logs, metric names/tags, configured trace attributes, audit/outbox/database rows, and serialized diagnostics for raw email/phone, Human Identity ID, credentials, authorization code/verifier, refresh/session token, private key, provider reference, and cross-app subject. The compact access token is permitted only in the typed successful internal result in W-6.
2. Decode successful test JWTs and assert exact key sets recursively; scan header/payload for forbidden values and nested unknown data. Scan JWKS for private `d` and any non-allowlisted member.
3. Validate all OAuth/JWKS schemas, fixtures, catalog, and semantic rules; the contract-bundle digest remains unchanged.
4. Run clean `test`, PostgreSQL 18 `integrationTest`, `contractTest`, `check`, `contractBundle`, architecture tests, 80%+ line/branch coverage, dependency policy/SBOM, secret scan, conflict-marker/diff inspection, full-context enable/disable/restart tests, and independent correctness and security reviews. No unresolved critical, high, or medium finding is acceptable.

## Explicit exclusions and later obligations

W-6 deliberately excludes:

- the public token endpoint and Spring Authorization Server token authentication provider;
- authorization-code parsing/consumption changes or an OAuth2AuthorizationService bridge;
- DPoP proof parsing, signature/`htu`/`htm`/`iat`/nonce/`ath` validation and replay persistence;
- bearer native tokens or optional `cnf`;
- refresh tokens/families, ID tokens, OIDC discovery/UserInfo, introspection, revocation, device authorization, dynamic registration, and client credentials;
- App Activation, onboarding/outbox/snapshot/UMS/profile/member behavior;
- product roles, permissions, profile claims, multi-resource/multi-audience or portfolio-wide tokens;
- private-key/JWT persistence, remote JWKS fetching, key administration/creation, KMS/HSM/cloud selection, deployment, commit, or push.

W-7 must provide the only token HTTP path and prove that a valid DPoP proof, one successful code redemption, stable subject resolution, current active identity/security version, and W-6 signing are composed without a bearer fallback or unsafe pre-consumption lookup. The operational trade-off for a runtime signer failure during that workflow must be made explicit and tested there; W-6 does not claim transactionality it cannot supply.

## Human decisions and blockers

There is no human design blocker for W-6. The exact cloud signer/KMS/HSM remains intentionally undecided because another workstream owns cloud choices. The repository boundary is stable: an externally provided, self-checked ES256 capability in production-like profiles and an isolated test/development adapter only where explicitly enabled.
