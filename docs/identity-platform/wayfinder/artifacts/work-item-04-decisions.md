# W-4 implementation decisions — single-use authorization code

Status: implementation-ready preflight  
Work item: [W-4 — Complete the single-use authorization-code journey](../work-items.md#w-4--complete-the-single-use-authorization-code-journey)  
Depends on: accepted W-3 registration ports and V5 canonical registration authority  
Runtime baseline: Java 25, Spring Boot 4.1.1, Spring Authorization Server 7.1.1, PostgreSQL 18

## Scope and stop line

W-4 adds the authorization-request/code portion of the `authorization` module, Flyway V6, and protocol/application tests. A registered first-party native client can submit an authorization-code request for an already authenticated IAM Human Identity. IAM persists the bound request, returns one opaque code through the registered redirect, and can atomically validate and consume that code exactly once through an internal application port.

W-4 does **not** issue an access token, refresh token, ID token, App Subject, activation, onboarding event, DPoP nonce, or DPoP proof result. It adds no login, consent, credential, or deterministic-fixture authentication bypass. `/oauth2/token` remains denied by the foundation chain; W-7 must compose successful code consumption and signed access-token issuance into one transactionally safe token endpoint. A non-standard HTTP “validate-only” token response is forbidden.

## Authoritative registration and principal inputs

Authorization code logic consumes only `RegistrationRegistry.findByClientId` and its immutable `RegistrationManifest`; it does not parse a manifest or read W-3 JDBC packages/tables. The accepted request must match one coherent registered tuple:

- configured issuer;
- `appRegistrationId`, derived from the registration, never supplied by the browser;
- `client_id`;
- `response_type=code`;
- `grant_type=authorization_code` at redemption;
- one exact registered `redirect_uri`;
- registered resource audience and a non-empty subset of registered scopes;
- registered `S256` PKCE method; and
- authenticated IAM `IdentityReference`.

The public authorization endpoint never selects an identity from a request parameter. It requires a non-anonymous Spring Security `Authentication` that an IAM authentication adapter has mapped to an active `IdentityReference`. W-4 supplies only that typed principal contract. Protocol integration tests may install the principal with `spring-security-test`; production and development runtime contain no test filter, header principal, fixture auto-login, or default user. The deterministic identity fixture remains merely persisted test data.

Dutch is first-party and the pinned registration requires no separate consent screen in this slice. That decision suppresses consent only; it does not suppress authentication. If there is no authenticated principal, the endpoint returns the existing correlated `401 authentication_required` and creates no request/code.

## Protocol validation

### Request shape

Only an HTTP GET to `/oauth2/authorize` is accepted. Every security-sensitive parameter must occur exactly once. The closed request is `client_id`, `response_type`, `redirect_uri`, `scope`, `resource`, `state`, `nonce`, `code_challenge`, and `code_challenge_method`; unknown parameters, duplicate parameters, blank values, or oversized request/query input fail before persistence. The configurable request-size budget counts servlet-decoded parameter names and values, not raw transport octets; connector-level raw request-line limits remain deployment configuration. `response_mode` is absent (OAuth query response only), and prompt/OIDC claims are outside W-4.

`state` and `nonce` are mandatory opaque client values, each 16–256 characters in `[A-Za-z0-9._~-]`. They are never treated as text for logging or metrics. Scope uses the registered space-delimited token grammar, has no duplicate token, and is canonicalized to sorted single-space form only after membership validation. `resource` must be the exact registered HTTPS audience.

### Exact redirect comparison

The servlet container performs the one standard form/query percent-decode. The resulting Java string is compared byte-for-byte in UTF-8 with a value returned by the W-3 registration port. A normally encoded raw query therefore yields the canonical registered string and succeeds; a client-supplied percent-encoded spelling is encoded on the wire a second time, decodes only once to the percent spelling, and fails. There is no URI normalization, case folding, percent re-encoding, application-level second decode, prefix/suffix match, wildcard, default-port equivalence, or trailing-slash forgiveness. Duplicates fail. A fragment, userinfo, alternate environment, scheme case/path case variation, double-encoded spelling, prefix, or suffix therefore fails.

If the client or redirect is unknown/mismatched, IAM must not redirect to the supplied URI. It returns a generic correlated JSON `400 invalid_request`. Only after the redirect has been proven exact may an OAuth error be returned to that registered redirect; externally distinguishable errors remain bounded to standard `invalid_request`, `unauthorized_client`, `unsupported_response_type`, `invalid_scope`, and `temporarily_unavailable`, with no protected value.

### S256 grammar and proof

Authorization requires `code_challenge_method=S256`. `plain`, missing, repeated, case variants, or unknown methods fail. The challenge is exactly 43 unpadded base64url characters `[A-Za-z0-9_-]`, decodes to exactly 32 bytes, and is re-encoded canonically before acceptance.

Redemption requires one `code_verifier` of 43–128 ASCII characters using RFC 7636 unreserved grammar `[A-Za-z0-9._~-]`. Compute `BASE64URL-NOPAD(SHA-256(US-ASCII(verifier)))`, decode both calculated and persisted challenges to 32 bytes, and compare in constant time. Never trim, Unicode-normalize, URL-decode twice, accept base64 padding, or accept `plain`. Verifier/challenge values never enter logs, error bodies, audit facts, or metrics.

## V6 persistence model

Create `V6__authorization_request_and_code.sql`. All timestamps are `timestamptz`, lengths are bounded, enum-like columns have check constraints, and every foreign key/index/constraint is named. V6 asserts the prerequisite roles, makes `iam_migrator` owner, revokes PUBLIC, and grants `iam_runtime` no direct INSERT/UPDATE/DELETE/TRUNCATE or sequence authority.

V6 also owns the singleton `authorization_server_issuer` authority, pinned to the portfolio contract issuer `https://iam.distracted.invalid`. Both issuance and redemption must match this row; a caller-supplied arbitrary HTTPS issuer is never authoritative. A future issuer change therefore requires an explicit reviewed migration and coordinated contract/configuration rollout rather than runtime self-registration.

### `authorization_request`

| Column | Rule |
|---|---|
| `authorization_request_id text` | primary key, opaque `arq_` identifier |
| `issuer text` | exact configured issuer, bounded |
| `app_registration_id text` | FK to V5 app registration |
| `client_id text` | FK/coherent registration binding |
| `resource_id text`, `resource_audience text` | coherent W-3 resource binding |
| `human_identity_id text` | FK to IAM identity; never leaves IAM |
| `redirect_uri text` | exact accepted registered string |
| `scope text` | canonical sorted registered subset |
| `state_digest bytea`, `nonce_digest bytea` | 32 bytes each; no raw state/nonce at rest |
| `code_challenge bytea` | decoded 32-byte S256 challenge |
| `code_challenge_method text` | exactly `S256` |
| `status text` | `AUTHORIZED` or `EXPIRED`; no invented pending/consent workflow |
| `authorized_at`, `expires_at` | database-clock timestamps, `expires_at > authorized_at` |
| `correlation_id text`, `version bigint` | typed/bounded ID; version starts at 1 |

The request is inserted as `AUTHORIZED` in the same transaction as its one code. Expiry is derived from the database clock; an expired request may be marked `EXPIRED` only by the consumption function. There is no mutable browser session row in W-4.

### `authorization_code`

| Column | Rule |
|---|---|
| `authorization_code_id text` | primary key, opaque `acd_` lookup identifier |
| `authorization_request_id text` | unique FK; exactly one code per request |
| `code_digest bytea` | 32-byte HMAC digest, unique with key version |
| `digest_key_version smallint` | positive version used at issuance |
| `status text` | `ISSUED`, `CONSUMED`, or `EXPIRED` |
| `issued_at`, `expires_at`, `consumed_at` | DB-clock values; consumed time iff `CONSUMED` |
| `consumed_correlation_id text` | present iff consumed |
| `version bigint` | 1 on issue; incremented exactly once on terminal transition |

Bindings remain in the immutable request row; the code row cannot be reparented. Keep expired/consumed rows for the platform retention period so replay remains distinguishable internally, but expose the same external rejection.

## Code and digest construction

Generate a fresh 256-bit value with `SecureRandom` for every code. The wire form is `authorization_code_id + "." + BASE64URL-NOPAD(secret)`; the secret segment is exactly 43 characters. The non-secret ID supports indexed lookup. Persist neither the wire code nor secret.

Add a dedicated `AuthorizationCodeDigestCapability`; do not reuse identifier blind-index, verification-challenge, or token-signing keys. Its implementation is HMAC-SHA-256 with a versioned keyring, write-current/read-old behavior, explicit key references, startup self-check, and a new `AUTHORIZATION_CODE_DIGEST` capability purpose. Production-like startup with W-4 enabled and no externally configured usable capability fails closed; tests may inject deterministic non-production material.

The domain-separated input is the unambiguous length-prefixed encoding of `iam`, environment, `authorization-code`, `digest-v1`, authorization-code ID, and raw secret. Length-prefixing, rather than delimiter concatenation, is normative. The persisted key version chooses the read key. Compare digests in constant time. Key material, raw code, and computed digest are excluded from exceptions and diagnostics. This HMAC context is the code protection/AAD equivalent; authorization codes are not encrypted because no later operation needs recovery.

Use a configurable lifetime with a default of 120 seconds and permitted range 60–300 seconds. Configuration is parsed at startup. Issuance passes the duration to the database function; PostgreSQL `transaction_timestamp()` supplies `authorized_at`/`issued_at`, and the function computes both expiries. Application clocks never determine validity.

## Database authority and atomic operations

Expose two parameterized, `SECURITY DEFINER` functions owned by `iam_migrator`, each with fixed `search_path = pg_catalog, public`; revoke PUBLIC and grant EXECUTE only to `iam_runtime`:

1. `issue_authorization_code(...)` validates the coherent active identity and complete canonical W-3 registration tuple, locks the registration/identity as needed, inserts one request plus one protected code atomically, and returns only database timestamps/version. It receives protected digests/challenge bytes, never raw state, nonce, verifier, or code.
2. `consume_authorization_code(...)` locks the joined code/request row, verifies `ISSUED`, both expiries against one database timestamp, expected version, the configured issuer, the client-derived app/resource/scope registration, the token request's exact client and redirect, and its S256 verifier against the immutable challenge, then changes the code to `CONSUMED` and records correlation in one conditional statement. State and nonce are not token-request parameters: their digests stay bound through the immutable one-code-to-one-request FK and are returned only as protected attributes in the trusted tuple. On expiry the function terminally marks the still-issued code/request expired. It returns a closed result enum (`CONSUMED` or `REJECTED`) and the immutable trusted authorization tuple only on `CONSUMED`.

The application parses the code ID, computes/verifies its HMAC, validates the verifier and request bindings, then invokes consumption. A malformed/unknown code, wrong digest/key version, wrong verifier, mismatch, expiry, already-consumed code, or concurrent loser all map to the same `invalid_grant` application result. No preflight “is valid” operation exists. PostgreSQL row locking plus one conditional state transition—not JVM locks—gives exactly one winner across threads, instances, and restarts.

No authorization outbox event is emitted. Add the allowlisted PII-free audit facts `AUTHORIZATION_CODE_ISSUED` and `AUTHORIZATION_CODE_CONSUMED`; facts contain authorization-request/code IDs, app/client IDs, result category, correlation/causation IDs, and timestamps, never identity ID, redirect query data, state, nonce, challenge, verifier, code, digest, identifier, or token. The state change and audit fact commit together. Rejected probes do not create durable per-attempt audit rows that could amplify storage; they increment a bounded-reason metric and emit a redacted operational log.

## Application ports and Spring Authorization Server integration

The authorization module exposes immutable ports, with JDBC adapters under `authorization.adapter.jdbc`:

- `AuthorizationRequestService.authorize(AuthenticatedIdentity, AuthorizationRequestCommand)` returns a one-use redirect result containing the raw code and original state only in memory;
- `AuthorizationCodeRepository.issue(ProtectedAuthorizationRequest, ProtectedAuthorizationCode)`;
- `AuthorizationCodeRedemption.redeem(AuthorizationCodeRedemptionCommand)` returns either a generic rejection or a trusted consumed tuple for W-7; and
- `AuthorizationCodeDigestCapability` as described above.

Use Spring Authorization Server's official `OAuth2AuthorizationEndpointFilter`/provider pipeline and `RegisteredClientRepository` extension point. The W-3 adapter constructs an immutable SAS `RegisteredClient` from the canonical registration: public client, `ClientAuthenticationMethod.NONE`, authorization-code grant, exact redirect, S256 required, and consent not required. Do not use `InMemoryRegisteredClientRepository`, generated passwords, an in-memory authorization service, an ephemeral signing key, or a fallback issuer.

W-4 installs Spring Authorization Server's `OAuth2AuthorizationEndpointFilter` with a dedicated authentication converter and provider. That provider calls `AuthorizationRequestService` directly and returns the official authorization-code result token; raw code is transient only during successful redirect construction. W-4 deliberately does **not** register an `OAuth2AuthorizationService`: its general `findByToken` shape would introduce a pre-consumption lookup seam while the token endpoint is still closed. Lookup by a presented code remains solely inside `AuthorizationCodeRedemption`, which parses the opaque code ID, verifies the protected digest, and atomically consumes through the database port without scanning by raw value. W-7 must add a deliberately constrained `OAuth2AuthorizationService`/token-provider bridge only when redemption and signed token issuance can complete as one safe workflow. Protocol-framework objects stay at the web adapter boundary; domain/JDBC code has no Spring Authorization Server types.

Install the authorization-server security chain only when an explicit W-4 feature property is enabled and the canonical registration plus digest capability are healthy. It matches `/oauth2/authorize` only in W-4. CSRF, saved-request, and request-cache behavior must not create an authentication mechanism. `/oauth2/token`, `/oauth2/jwks`, OIDC discovery, UserInfo, introspection, revocation, device endpoints, and dynamic registration remain under deny-all. W-7 will add the official token endpoint provider and must consume `AuthorizationCodeRedemption` in the same successful issuance workflow; it must not validate then lose the consumed code before issuing a token.

## Errors, correlation, and privacy

Correlation handling reuses `CorrelationIdFilter`: accept a valid incoming ID or generate one, echo it in the response, and carry it into persistence/audit. OAuth redirects include only `code` and the original `state` on success. The code necessarily appears once in the registered redirect `Location`; it never appears in a response body, log, exception, metric, trace attribute, audit/outbox payload, database statement text, or database value. Configure access logging and observation sanitization so query strings and `Location` values for the authorization endpoint are not recorded.

Invalid requests use safe bounded reason codes in metrics/logs (`redirect_mismatch`, `pkce_invalid`, `binding_mismatch`, `expired`, `invalid_grant`, `temporarily_unavailable`). Logs may include opaque app/client/request/code IDs and correlation ID, but never identity ID or any request value that can carry PII. Database and cryptographic failures produce generic correlated errors without SQL, constraint, stack, key reference/material, or protected values.

## TDD and acceptance matrix

Capture RED evidence before implementation, then GREEN/refactor evidence in a W-4 artifact.

### Unit/protocol

1. Parameterize the exact Dutch redirect positive and case, encoding, double-encoding, prefix, suffix, slash, query, fragment, userinfo, wildcard, scheme, hostname, environment, duplicate/missing redirect negatives.
2. Parameterize valid 43–128-character verifiers and missing/plain/case/padded/malformed/short/long/non-ASCII challenges/verifiers; independently check the RFC 7636 S256 known vector and constant-time comparison path.
3. Reject duplicated/unknown parameters; wrong response type/grant/client/app/resource/scope/issuer; missing or swapped state/nonce; cross-request code, redirect, challenge, or principal binding.
4. Prove the W-3 registration adapter creates only the pinned public authorization-code/S256 client and cannot create a secret/refresh/implicit client.
5. Prove absent/anonymous/wrong-shaped principal creates no rows. Prove deterministic fixture enablement does not authenticate a browser request.
6. Prove the domain has immutable values, no JDBC/SAS dependency, no raw secret/code getters on persisted models, and no access/refresh/token signer/App Subject/activation code.

### PostgreSQL 18 integration

1. Clean V1–V6 and upgrade V1–V5→V6 migrations create exact constraints, owners, revocations, grants, function signatures, and fixed search paths; migration without prerequisite roles fails.
2. Exercise every invalid length/state/time/digest/key-version/FK/coherence constraint and every SELECT/INSERT/UPDATE/DELETE/TRUNCATE/EXECUTE combination for runtime, migrator, PUBLIC, relay, reconciler, and unrelated roles.
3. Issue once and verify request/code atomicity, DB-derived lifetime, no raw code/state/nonce/verifier at rest, rollback on failure before/between/after inserts, and no duplicate request code.
4. Correct redemption wins once; sequential replay and wrong verifier return the same rejection without mutation. Barrier-synchronized concurrent correct redemptions across separate connections produce exactly one consumed result and all other generic rejections.
5. Expiry boundary uses database time, terminalizes once, and cannot be resurrected. Restart a full application context against the same database and prove the issued code remains redeemable once (or remains consumed/expired).
6. Rotate the digest write key while retaining the old read key and redeem an old code; missing old key fails closed without consuming. New codes use only the current version.

### HTTP and privacy

1. With an authenticated test principal, exact request returns a `302` only to `dutch://oauth/callback` with one code/state; no body or cacheable response. Every redirect/PKCE/mix-up negative has the pinned safe status/destination behavior and correlation header.
2. Without authentication, return correlated `401`; invalid exact-redirect proof never redirects. POST and encoded path variants are denied. `/oauth2/token` and every excluded authorization-server path remain denied and issue no token.
3. Capture response bodies/headers, database rows, audit/outbox rows, structured logs, metrics, and traces. Canary-scan for raw email/phone, identity ID, state, nonce, challenge, verifier, raw/digest code, credentials, access/refresh token, secret, and private key. The sole permitted raw-code occurrence is the one successful registered `Location`, which the access-log test proves is redacted.
4. Contract tests keep the W-3 metadata/schema/catalog digest unchanged, continue advertising only authorization code plus S256/no refresh, and prove W-4 adds no published API/event contract.

### Verification gate

Run `test`, PostgreSQL 18 `integrationTest`, `contractTest`, architecture tests, 80%+ coverage gates, migration validation/upgrade/restart, dependency verification/SBOM, secret scan, and final diff check. Independent correctness and security review must have no unresolved critical/high finding.

## Human decisions and external blockers

There is no human design blocker for W-4. Deployment must eventually supply the external authorization-code HMAC capability and a real upstream authentication journey before this endpoint is production-usable, but neither is a reason to invent fallback material or a login UI in this item. Cloud/KMS/vendor selection remains deliberately outside this repository decision.
