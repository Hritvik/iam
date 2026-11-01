# W-7 implementation decisions — native DPoP and durable replay protection

Status: implementation-ready preflight  
Work item: [W-7 — Enforce native DPoP and durable replay protection](../work-items.md#w-7--enforce-native-dpop-and-durable-replay-protection)  
Depends on: accepted W-4 code redemption, W-5 App Subject resolution, W-6 token/JWKS/signing, and their migration-owned registration and issuer authorities  
Runtime baseline: Java 25, Spring Boot 4.1.1, Spring Authorization Server 7.1.1, PostgreSQL 18

## Scope and stop line

W-7 completes the first-party native OAuth exchange. It validates a DPoP proof, atomically consumes one authorization code and one server nonce, records the proof replay identity, resolves the stable App Subject and current active-identity security version, signs the closed W-6 token, appends a PII-free issuance audit fact, and returns a DPoP-bound access token. It also supplies an IAM-internal protected-request verifier that requires `ath` and durable replay protection when a resource presents that token.

W-7 **does open** `POST /oauth2/token`, through Spring Authorization Server's official `OAuth2TokenEndpointFilter` with a deliberately constrained authorization-code converter/provider. It supports only the pinned public first-party client, `grant_type=authorization_code`, client authentication method `none`, the exact registered redirect, PKCE verifier, and a mandatory `DPoP` header. A general lookup/validation-only endpoint and a bearer-token branch are forbidden. The successful response contains `access_token`, `token_type: DPoP`, `expires_in`, and the canonical granted `scope`; it never contains a refresh token, ID token, identity ID, App Subject as a separate field, profile data, or arbitrary extensions.

W-7 does not activate an app, emit onboarding, create sessions or refresh families, add OIDC/UserInfo/introspection/revocation/device/client-credentials/dynamic-registration support, or expose a protected product resource. The protected-request verifier is an internal port for later IAM/resource adapters; no test-only public validation endpoint is added. W-8 remains the activation/onboarding boundary.

The endpoint and proof wire shapes are externally observable. Before implementation, add the smallest language-neutral contracts needed for the standard exchange: a closed DPoP token-response schema, OAuth token-error schema, and closed DPoP protected-header/token-proof/resource-proof claim schemas. They describe RFC 9449/RFC 6749 fields without publishing IAM persistence or implementation details. Catalog, semantic requirements, valid/invalid fixtures, and the contract digest change additively and intentionally; Dutch or another client consumes the versioned bundle rather than an editable copy.

## Closed DPoP proof model

Parse the compact proof with strict duplicate-member detection and hard size bounds before cryptographic work. It has exactly three base64url segments and no padding. The protected header is exactly:

```json
{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"...","y":"..."}}
```

Reject `kid`, `jku`, `x5u`, `x5c`, `crit`, `b64`, compression, unprotected headers, private `d`, symmetric/RSA/EdDSA keys, `none`, algorithm negotiation, unknown members, non-canonical coordinates, invalid points, and malformed/non-canonical JOSE signatures. `x` and `y` are canonical unpadded base64url encodings of exactly 32 bytes. Verify ES256 over the original encoded header and payload using only the embedded public key.

Compute the key binding with the RFC 7638 SHA-256 JWK thumbprint over the exact canonical member order `{"crv":"P-256","kty":"EC","x":"...","y":"..."}` and encode it as 43 unpadded base64url characters. This is the sole `DpopKeyThumbprint` supplied to W-6; caller-provided thumbprints are never accepted.

Token-endpoint proof claims are exactly `jti`, `htm`, `htu`, `iat`, and `nonce`. `ath` is forbidden there because the request does not yet present an access token. Protected-resource proof claims are exactly those five plus mandatory `ath`. Unknown, duplicated, nested, null, floating-point/exponent, or wrong-type members fail closed.

- `jti` is 22–128 canonical base64url characters. A server cannot prove client randomness, so the implementation claims only minimum encoded material and durable uniqueness, not statistical client entropy.
- `htm` is uppercase ASCII and must equal the effective request method exactly. The token proof is always `POST`.
- `htu` is an absolute HTTPS URI containing scheme, authority, and path only. Userinfo, query, and fragment are forbidden. Comparison is against a trusted server-derived expected URI, not arbitrary `Forwarded`/`X-Forwarded-*` input. The public token endpoint URI is configured once, validated at startup, and must equal the migration-owned issuer plus `/oauth2/token`. Scheme and host are lowercase, the default HTTPS port is absent, the path is dot-segment free, and percent-encoding is canonical without decoding reserved path data. The same normalizer creates both expected and presented comparison forms.
- `iat` is an integral NumericDate. Sample the verifier clock once. Default maximum age is 60 seconds and future skew is 5 seconds; configuration ranges are 10–120 and 0–30 seconds respectively. Exact boundaries, rollback, overflow, decimals, and exponent encodings are tested.
- `nonce` is mandatory for an authorization effect. It is a canonical opaque server value, not an authorization-request OIDC nonce.
- `ath` is `BASE64URL(SHA-256(ASCII(compact_access_token)))`, compared in constant time. It is mandatory only when an access token is presented and must bind to the already strictly verified W-6 token whose `cnf.jkt` equals the proof-key thumbprint.

Proof/domain values are immutable and have redacted renderings. No API exposes the embedded key, thumbprint, `jti`, nonce, `ath`, or compact proof after verification.

## Nonce challenge and lifecycle

Use RFC 9449's nonce retry flow rather than accepting a proof with no server freshness value. A first cryptographically valid, time/target/method-valid token request with a missing, expired, wrong, or already-consumed nonce receives the standard OAuth error `use_dpop_nonce`, a fresh `DPoP-Nonce` response header, `Cache-Control: no-store`, and the normal correlation header. It does not inspect or consume the authorization code. Unknown and valid-looking codes receive the same nonce challenge so the challenge is not a code oracle.

The challenge request's proof replay identity is durably claimed when the fresh nonce is created; the retry must use a new proof `jti`. A nonce is 32 CSPRNG bytes encoded as 43 unpadded base64url characters, valid for 120 seconds by default (accepted range 30–300), single use, and bound to purpose `TOKEN`, canonical client/app, proof-key thumbprint, method, and target. Issuing a new nonce supersedes any prior live nonce for that binding. The raw nonce exists only in the response header and caller memory.

For future protected-resource adapters, use the same internal service with purpose `RESOURCE`, resource audience, proof-key thumbprint, method, and normalized target binding. W-7 supplies the port and persistence behavior but does not publish a generic nonce or resource-validation HTTP endpoint.

Protect nonce and replay lookup material through one purpose-separated, versioned external `DpopStateDigestCapability` (HMAC-SHA-256 or stronger). Production-like profiles fail startup without it; there is no default key, signer-key reuse, code/identifier-key reuse, hardcoded secret, raw SHA lookup fallback, or ephemeral production material. Tests use an explicitly test-scoped capability. Key rotation writes the current version, reads retained versions, and fails closed without mutating state when an old key is unavailable.

## V9 persistence and least authority

Add forward-only `V9__dpop_nonce_replay_and_token_issuance.sql` with focused tables:

```text
dpop_nonce
  nonce_id, digest, digest_key_version, purpose,
  app_registration_id, client_id, proof_key_thumbprint_digest,
  method, target_digest, status, expires_at, consumed_at,
  version, created_at, correlation_id

dpop_replay
  replay_digest, digest_key_version, purpose,
  expires_at, created_at

token_issuance_audit_fact
  audit_id, authorization_code_id, app_registration_id, client_id,
  outcome='SUCCEEDED', correlation_id, occurred_at
```

All identifiers, enums, lengths, versions, time ordering, and terminal-state coherence have literal constraints. `dpop_nonce` has one live binding under a partial uniqueness rule and immutable binding/digest columns; only the `ISSUED -> CONSUMED|EXPIRED|SUPERSEDED` transition is allowed. `dpop_replay.replay_digest` is the primary key and the table is insert-only except bounded expiry deletion. It stores no raw `jti`, JWK, thumbprint, nonce, method/URI, access token, `ath`, code, identity, or subject. The token issuance audit is immutable and unique per authorization code; it stores no token `jti`, token, subject, identity, proof, nonce, verifier, redirect, state, or arbitrary detail.

Database time is authoritative for nonce expiry, replay expiry, and audit time. Replay expiry is at least proof maximum age plus maximum skew and a small safety margin; default retention is 180 seconds and accepted range 120–600. A security-definer cleanup function deletes only expired replay/nonces in a configured bounded batch (maximum 1,000), never as an unbounded request-path scan.

Security-definer functions owned by `iam_migrator`, fully qualified and fixed to `search_path=pg_catalog, public`, provide: nonce issue/supersede, atomic nonce consume plus replay claim, resource replay claim, issuance-audit append, active identity/security-context read, and bounded cleanup. Revoke PUBLIC. `iam_runtime` receives EXECUTE only and no direct table privileges; `iam_registration_reconciler`, `iam_outbox_relay`, unrelated roles, and PUBLIC receive none. `iam_migrator` owns/maintains state. Exact function ACLs and every table operation are tested literally.

## Token-endpoint composition and transaction semantics

Use the official Spring Authorization Server token filter with one closed converter/provider. The converter accepts only one value for `grant_type`, `code`, `redirect_uri`, `client_id`, and `code_verifier`, rejects unknown/duplicate/body/query-confused parameters, rejects client secrets and Authorization credentials, and takes DPoP only from the single `DPoP` header. Bound decoded input and raw request size before JSON/JWT or database work. The token response uses Spring's OAuth response path but a custom closed generator; do not install an in-memory authorization service, a broad `findByToken` lookup, or default refresh/ID token generators.

The orchestration has two phases:

1. **Nonce challenge transaction.** Strictly validate the proof except nonce, apply the bounded rate-limit port, claim its replay digest, issue/supersede the bound nonce, commit, and return `use_dpop_nonce`. It never reads or changes the authorization code.
2. **Issuance transaction.** Strictly validate the proof and derive its thumbprint/digests before beginning state changes. In one short local Spring transaction using the same IAM datasource/connection participation: atomically claim replay and consume the bound nonce; call W-4 redemption; call W-5 App Subject resolution; read and lock the same active identity/binding and current security version through the V9 authority; call the already self-checked W-6 signer; append one issuance audit; then commit. Only after commit may the compact token be placed in the OAuth response.

The W-5 resolver's identity/registration locks and the V9 context reader use one documented fixed lock order. The transaction holds those locks while signing so identity disablement, registration drift, subject mutation, code replay, nonce replay, and DPoP replay cannot interleave with issuance. The external signer call must have a strict bounded timeout; this is a deliberate short-transaction trade-off for the proving milestone. If proof, nonce, code, subject, identity, registration, context, or signing fails before commit, code consumption, nonce consumption, replay claim, new subject/audit, and issuance audit all roll back. The same code/proof/nonce may be retried only when no authorization effect committed. A signer may have computed a signature before a later local rollback, but that token is never returned or persisted.

If the database commit fails, discard the in-memory token. If the HTTP connection fails after commit, the one-use code remains consumed and the token is not recoverable; W-7 does not persist or replay raw credentials. This standard one-shot failure mode is explicit and tested. Do not add a token-result cache, raw-token audit, or code resurrection.

The success response is `200 application/json`, `Cache-Control: no-store`, `Pragma: no-cache`, no cookies, and an echoed/generated correlation ID. `expires_in` is derived from the W-6 issued timestamps, not request input. Standard OAuth errors are closed: `invalid_request`, `invalid_client` only for malformed public-client presentation (without enumeration), `invalid_grant`, `invalid_dpop_proof`, `use_dpop_nonce`, and `temporarily_unavailable`. Messages are fixed and contain no submitted value or internal detail. Redirect-style errors are never used at the token endpoint.

Rate limiting is mandatory before expensive proof/database/signing work through a bounded port. Non-production may use the existing bounded-cardinality local adapter; production-like profiles require an external/distributed implementation or fail closed until the cloud workstream supplies one. Keys are protected/bounded client and network buckets, never code, proof, JWK, token, identity, subject, or raw address telemetry. Retry/nonce challenges have separate bounded budgets to prevent database amplification.

## Protected-resource verification port

`DpopProtectedRequestVerifier` accepts a compact W-6 access token, one DPoP proof, trusted expected method/target/audience/app/client/security version, and correlation context. It first strictly verifies the access token with W-6, then validates proof signature/header/claims, exact method/target/time/nonce, `ath`, and `cnf.jkt`, and finally atomically consumes the nonce and claims replay before returning a typed verified app-scoped principal. No raw token, proof, identity ID, JWK, or nonce is returned. Sequential, concurrent, cross-instance, and post-restart reuse has exactly one winner.

Failures before durable replay claim have no state except a nonce challenge where applicable. A successful replay claim commits before a protected action is authorized. Product/resource code receives only the verified App Subject, app/client/audience, scope, security version, and bounded authentication metadata. This port does not query UMS, Ledger, profiles, roles, or product data.

## Privacy and observability

The compact access token is permitted only in the successful token response and typed internal verifier input. The raw nonce is permitted only in `DPoP-Nonce`; the successful proof is permitted only in its request header. Access logs and HTTP observations redact the token response body, `DPoP`, `Authorization`, `DPoP-Nonce`, submitted code/verifier, and all request bodies/query strings. No one logs a `Location` or header map wholesale.

Logs, errors, metrics, traces, audits, replay/nonce rows, and serialized diagnostics contain none of: raw identifier, Human Identity ID, App Subject, code/verifier, state/OIDC nonce, access/refresh/session token, DPoP compact proof, embedded JWK/coordinates, thumbprint, DPoP nonce, `jti`, `ath`, private/signing/digest key, provider reference, or cross-app subject. Operational labels use only bounded reason enums and feature/purpose categories. Correlation IDs are validated/generated and may be carried separately.

Rejected probes do not append durable per-attempt audit facts. Metrics use bounded reasons; logs use fixed messages. Database, crypto, signer, and framework exceptions are translated to fixed OAuth responses without SQL, constraint, stack, key/provider, or submitted data. Domain/command/result objects and Jackson diagnostic serialization are redacted.

## TDD acceptance matrix

Every production increment requires an observed behavioral RED followed by minimal GREEN/refactor evidence. Compilation failures and already-green assertions do not count as RED.

### Unit, property, and protocol

1. Literal header/claim matrices cover missing/extra/duplicate/null/wrong-type members, size/base64/segment bounds, private/invalid/non-P-256 JWKs, wrong `typ`/algorithm, signature mutation/malleability, invalid point/coordinate encoding, and RFC 7638 thumbprint vectors.
2. Method and URI matrices cover case, query/fragment/userinfo, default/non-default ports, IDN, percent encoding/double encoding, dot segments, trailing slash, proxy/forwarded-header spoofing, and token-endpoint exactness.
3. Time tests cover exact age/future-skew boundaries, one clock sample, decimals/exponents, integer overflow, rollback, expiry, and configuration bounds. `jti`, nonce, digest/key-version, and `ath` grammars have length/encoding/property tests and constant-time equality paths.
4. Token proofs require nonce and forbid `ath`; resource proofs require both nonce and `ath`. Wrong key/thumbprint/token/method/target/app/client/audience/scope/security version and cross-token/cross-app/cross-purpose swaps fail.
5. Converter tests cover duplicate/unknown/query parameters, client secret/basic auth, unsupported grants, missing/multiple DPoP headers, oversized requests, safe errors, and no value echo.
6. Architecture tests prove one official token filter/provider, no bearer/default token generator, no broad authorization lookup, no refresh/OIDC/client-credentials path, no public proof-validation endpoint, parameterized SQL only, and no raw artifacts in renderings/serialization.

### PostgreSQL 18, migration, and transaction

1. Clean V1–V9 and populated V1–V8→V9 upgrade equivalence, preservation, rerun, missing-role failure, full-context restart, owners, fixed search paths, volatility/security-definer flags, literal function ACLs, and every table operation across migrator/runtime/reconciler/relay/unrelated/PUBLIC.
2. Literal matrices exercise every NOT NULL/check/PK/unique/FK/status/time/version/immutability/restrict-delete constraint and every nullable function argument. Raw proof/token/nonce/`jti`/JWK/identity/subject canaries are absent from all V9 rows.
3. Nonce issue/supersede/expiry/consume and digest-key rotation are proven with database time. Missing old key fails without mutation. Concurrent consume has one winner.
4. Replay insert has one winner sequentially, across barrier-synchronized connections, after full-context restart, and after key rotation; cross-purpose/token/method/target inputs cannot alias. Bounded cleanup removes only expired rows and never exceeds its batch.
5. Inject failures before and after replay, nonce, code, subject, signer, issuance audit, and commit boundaries. Assert complete rollback, except the explicitly committed nonce-challenge phase. Signer timeout/failure and database commit failure return no token.
6. Deterministically overlap identity disablement, registration drift, code redemption, subject creation, nonce/replay, and issuance; prove the fixed lock order has no deadlock and exactly one coherent winner.

### HTTP, restart, contracts, and privacy

1. Real HTTP tests perform nonce challenge then successful retry and assert exact `DPoP-Nonce`, OAuth error/success JSON, cache headers, correlation, token type, lifetime, scope, no cookies, and no refresh/ID token. GET/PUT, encoded path, wrong content type, query-confused form, anonymous/secret client, and excluded endpoints are denied.
2. Sequential/concurrent/restart code/proof/nonce replay tests have one token winner. Failed signing leaves code/nonce/proof reusable; post-commit response loss leaves the code consumed and never stores a token.
3. Resource-port tests verify correct `ath`/`cnf.jkt` and reject every binding/replay mismatch across restart and instances without exposing a public debug endpoint.
4. Canary-capture request/response bodies and headers, persistence/audit/outbox, structured logs, metric names/tags, configured trace attributes, and serialized diagnostics. Assert the only raw credential locations are the permitted transient request/success response/header positions.
5. Validate the additive DPoP/token contracts, catalog, semantic requirements, valid/invalid fixtures, and reproducible new digest. Existing registration, access-token, JWKS, event, and error contracts remain backward compatible.
6. Run clean `test`, PostgreSQL 18 `integrationTest`, `contractTest`, `check`, `contractBundle`, architecture rules, 80%+ line/branch coverage, dependency policy/SBOM, secret scan, conflict/diff inspection, and independent correctness/database/security reviews. No unresolved critical, high, or medium finding is accepted.

## Explicit exclusions and later obligations

W-7 excludes refresh-token issuance/families/rotation/reuse response, sessions/logout, ID tokens, OIDC discovery/UserInfo, introspection, revocation, device flow, dynamic registration, client credentials, multiple audiences, bearer native tokens, product roles/profile claims, app activation, onboarding/outbox/snapshot/relay, UMS/member/profile behavior, and public generic DPoP validation/nonce/debug endpoints.

It also excludes cloud/KMS/HSM selection, provider credentials, distributed rate-limit vendor selection, external proxy topology, deployment/SLO/alerts/runbooks, commit, push, and publication. Production deployment remains blocked until the cloud workstream supplies the external signer, DPoP digest capability, distributed limiter, trusted public-origin/proxy configuration, and their operational controls. None receives an insecure fallback.

W-8 may consume the trusted app/identity/subject context internally for activation, but it must not weaken DPoP, add identity/profile claims, or reuse proof/replay state as activation evidence. Product services validate access tokens and DPoP through a separately authorized adapter; they never access IAM replay tables.

## Human decisions and blockers

There is no human design blocker. The standards-constrained choices are settled: DPoP is mandatory, nonce-backed, ES256/P-256, durable, and sender constrained; `/oauth2/token` opens only with the complete W-4/W-5/W-6 composition; refresh and bearer paths remain absent. Cloud-specific signer, digest-key custody, distributed rate limiting, and proxy deployment are intentionally owned by the parallel cloud workstream and are represented here only as required fail-closed ports.
