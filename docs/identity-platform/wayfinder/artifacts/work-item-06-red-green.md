# W-6 RED → GREEN evidence — closed signed human access token

Status: implementation candidate; independent correctness and security review still required  
Decision record: [work-item-06-decisions.md](work-item-06-decisions.md)

## Scope delivered

- Closed ES256 `at+jwt` issuance from a typed, already-consumed authorization context, resolved App Subject,
  positive security version, and mandatory canonical DPoP thumbprint.
- Canonical-registration revalidation and a narrow trusted App Subject binding port before signing.
- Exact JOSE header and recursive claim allowlists; scalar audience; bounded lifetime and verification skew;
  CSPRNG-backed 144-bit `jti`; safe redacted values and errors.
- Independent strict verifier pinned to P-256/ES256 and an exact `kid`, with duplicate JSON-member detection.
- Explicit external `AccessTokenSigningCapability`, startup self-check, active-key verification, and no production
  key generator or private-key fallback.
- Contract-shaped sorted public JWKS at `GET`/`HEAD /oauth2/jwks`, strong ETag, conditional `304`, public
  five-minute cache policy, `nosniff`, and no cookies/private/provider fields.
- Active/retiring-key overlap, cached-old/refreshed verifier, new-key-only signing, and old-key removal behavior.
- `/oauth2/token` and every W-7 concern remain outside this item and retain the foundation deny-all behavior.

V8 adds only the least-privilege read authority for the existing V6 issuer singleton. No token/key state,
issuance audit/outbox event, refresh token, ID token, OIDC endpoint, DPoP proof parser, activation, or public token
response was added.

## Observed RED → GREEN loops

### Closed issuance boundary

RED:

```text
./gradlew test --tests dev.distracted.iam.token.HumanAccessTokenIssuerTest
HumanAccessTokenIssuerTest > issuesExactClosedSenderConstrainedTokenFromCanonicalContext() FAILED
java.text.ParseException at HumanAccessTokenIssuerTest.java:50
1 test completed, 1 failed
```

The typed boundary existed only as a deliberately non-JWT stub, so the behavioral test could not parse a token.

GREEN:

```text
./gradlew test --tests dev.distracted.iam.token.HumanAccessTokenIssuerTest
BUILD SUCCESSFUL
```

The minimum implementation produced an ES256 JWS whose header, claims, signature, canonical registration tuple,
App Subject binding, lifetime, `jti`, and `cnf.jkt` matched the asserted closed profile.

### Repository-wide fail-closed negative coverage

RED:

```text
./gradlew clean test integrationTest contractTest check contractBundle dependencyPolicyCheck generateSbom secretScan
Rule violated for bundle iam: branches covered ratio is 0.75, but expected minimum is 0.80
BUILD FAILED
```

GREEN/refactor:

```text
./gradlew test jacocoTestCoverageVerification jacocoTestReport
BUILD SUCCESSFUL
```

The correction added negative matrices for every closed claim family, type/algorithm/key/signature tampering,
time and skew bounds, malformed/canonical DPoP values, unsafe signer metadata/material, authorization tuple drift,
missing binding, under-entropy material, disabled/enabled signer wiring, and active/retiring-key rotation. Final
coverage before the clean confirmation was 94.08% line and 80.03% branch.

### Independent-review correction cycle

The first independent review identified one HIGH issuer-authority defect and several MEDIUM fail-closed/evidence
gaps. The corrective matrix now covers each unsafe behavior explicitly:

- an arbitrary configured HTTPS issuer was accepted because the issuer was not compared with a trusted
  migration-owned issuer authority;
- external capability and context ports could throw provider-specific exceptions outside the safe boundary;
- the default issue-command record diagnostics exposed its nested `ConsumedAuthorization`, including the global
  Human Identity ID;
- public EC keys without explicit `use=sig` and `alg=ES256` metadata were accepted;
- floating JSON numbers such as `1.0` and exponent encodings could satisfy integer claim checks;
- the HTTP/restart/privacy acceptance matrix did not exercise the real Spring Security surface.

GREEN:

- `HumanAccessTokenIssuer` now requires both the configured issuer and a trusted
  `AuthorizationServerIssuerAuthority`; only exact equality with the migration-owned singleton proceeds. An
  arbitrary but syntactically valid HTTPS issuer fails with the fixed safe internal error.
- Capability construction and issuance-time capability/registration/binding/material failures are contained as
  fixed `invalid_context`, `signer_unavailable`, or `signing_failed` outcomes. Canary provider details are absent
  from errors and configured logs.
- Every issue-command component is excluded from Jackson diagnostics and the command has a fixed redacted
  rendering; canary global identity, subject, thumbprint, and correlation values are absent.
- Publisher and verifier require P-256 public keys explicitly marked `use=sig` and `alg=ES256`.
- Version, security-version, `iat`, and `exp` accept only integral Jackson number types; decimal and exponent
  encodings fail even when mathematically integral.
- Full Spring web contexts are closed and restarted with externally supplied old, then new-active/old-retained
  key sets. Real MockMvc requests prove JWKS GET/HEAD parity and denial of token, OIDC discovery, UserInfo,
  introspection, revocation, device authorization, and dynamic registration.
- Privacy canaries are scanned across response bodies/headers, configured application logs, and metric IDs/tags.
  An architecture rule proves the production token module outside its narrow issuer-authority JDBC adapter has no
  logging, metrics, tracing, JDBC, audit/outbox, or messaging dependency. Because W-6 creates no token,
  audit/outbox, or trace-exporter state, the evidence does not claim row/export capture for nonexistent surfaces.

### Second independent-review correction cycle

- V8 now owns `read_authorization_server_issuer()`: a fixed-search-path, `STABLE SECURITY DEFINER` function owned
  by `iam_migrator`, revoked from PUBLIC and executable only by `iam_runtime`. Runtime retains no direct table read.
  The production JDBC authority translates missing, duplicate, drifted, and database-failure states to one safe
  error. Real PostgreSQL tests cover the canonical value, role/function/table privileges, restart, tampered states,
  and diagnostics.
- Signing providers now expose one `AccessTokenSigningSnapshot`. Publication and issuance capture it once and use
  the same immutable purpose/algorithm/active `kid`/public-key set/signing operation for validation, output,
  signing, and produced-token verification. Deterministic changing-provider tests prove one read; private/wrong-use
  second snapshots cannot affect output, and kid/signing-key mismatch fails self-check.
- BigInteger conversion uses `longValueExact()` before NumericDate math or integer narrowing. Values above/below
  `long` and `int` ranges, decimals, and exponent encodings fail closed instead of wrapping.

### Final production-context restart proof

RED:

```text
AuthorizationCodePersistenceIntegrationTest
  > freshFullSpringContextsRehydrateProductionIssuerAuthorityAgainstSameDatabase() FAILED
NoSuchBeanDefinitionException: AuthorizationServerIssuerAuthority
```

The production configuration's `@ConditionalOnBean(JdbcTemplate)` was evaluated before JDBC auto-configuration,
so merely reconstructing adapter objects had hidden a real application-startup ordering defect.

GREEN:

```text
./gradlew integrationTest --tests \
  'dev.distracted.iam.authorization.AuthorizationCodePersistenceIntegrationTest.freshFullSpringContextsRehydrateProductionIssuerAuthorityAgainstSameDatabase'
BUILD SUCCESSFUL
```

Token issuer authority enablement now directly requires the runtime `JdbcTemplate`. The test closes a complete
Spring servlet context, creates a new context with the same PostgreSQL URL/runtime credentials, proves a distinct
production `JdbcAuthorizationServerIssuerAuthority` bean is rehydrated, and resolves the same migration-owned
issuer from both contexts. JDBC-free JWKS-only tests explicitly disable only the issuer-authority configuration.

## Verification matrix

- Exact header: only `typ=at+jwt`, `alg=ES256`, and the active URL-safe `kid`.
- Exact payload: the 14 published required claims only; no global identity, PII, credential, code, request,
  redirect, state, nonce, profile/member, role, correlation, or arbitrary claim.
- DPoP: mandatory canonical 32-byte SHA-256 thumbprint; there is no bearer branch.
- Verification: issuer, scalar audience, app/client, scope order/membership/grammar, subject shape, constants,
  security version, time bounds, `jti`, `cnf.jkt`, signature, curve, exact key ID, and unknown members fail closed.
- Signer: purpose/algorithm/key ID/key set/private material/duplicates/active-key membership/sign-and-verify
  self-check are validated before publication or issuance.
- JWKS: only `kty`, `use`, `alg`, `kid`, `crv`, `x`, and `y`; lexical ordering; deterministic strong ETag;
  GET/HEAD/304/cache/media/no-cookie behavior.
- Configuration: disabled W-6 has no JWKS publisher; enabled W-6 without an external signer fails startup; a
  healthy explicit signer starts a real web context without opening the token endpoint.
- Rotation: old tokens validate during overlap, new tokens use only the new active key, a stale cache rejects the
  new key, refreshed keys verify both, and removal rejects the old generation.
- Architecture/privacy: the endpoint opts into platform error handling; token values render redacted; production
  contains no signing-key adapter, logging, metrics, tracing, persistence, or token-response surface.

## Clean-gate result

The first full clean gate passed every functional and security task except coverage and thereby supplied the RED
above. After the negative-matrix correction, the full gate is rerun as the final confirmation. The already completed
test artifacts record:

- 278 unit tests, zero failures/errors;
- 270 PostgreSQL 18 integration tests, zero failures/errors;
- 8 contract tests, zero failures/errors;
- 94.17% line / 81.06% branch coverage;
- unchanged contract bundle SHA-256
  `fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f`.

## Remaining integration obligations

- W-7 must build the only public token endpoint and compose DPoP proof validation, one atomic code consumption,
  current active identity/security-version resolution, App Subject resolution, issuance audit, and this signer.
- The exact cloud KMS/HSM capability, credentials, key creation, rotation automation, and deployment remain in the
  separate cloud workstream.
- W-6 has no configured trace exporter or token HTTP response, so it does not claim capture of surfaces that do not
  exist. It adds no logs or metric tags containing tokens, `kid`, provider references, subjects, or thumbprints.
