# W-4 RED/GREEN evidence — single-use authorization code

Status: implementation candidate; independent correctness and security review pending  
Decision source: [work-item-04-decisions.md](work-item-04-decisions.md)

## Scope delivered

- Flyway V6 persists an immutable authorization request, a protected one-code row, and allowlisted PII-free authorization audit facts.
- `issue_authorization_code` validates active identity and the coherent W-3 registration tuple, uses PostgreSQL time, and atomically inserts request, protected code, and issuance fact.
- `consume_authorization_code` locks the joined request/code, checks issuer/client/exact redirect/S256 proof/digest/version/expiry, and gives exactly one terminal winner.
- The wire code contains a random opaque lookup ID and a 256-bit random value; only a purpose-separated, versioned HMAC-SHA-256 digest is persisted.
- Spring Authorization Server's `OAuth2AuthorizationEndpointFilter` and authentication-provider pipeline own `/oauth2/authorize`. No custom validation endpoint was added.
- The W-3 registry is exposed through an immutable SAS `RegisteredClientRepository` as a public authorization-code client with exact redirect and mandatory S256.
- `/oauth2/token`, JWKS, OIDC, device, introspection, revocation, and dynamic-registration endpoints remain under the foundation deny-all chain.

## Observed RED examples

Each production increment followed an observed behavioral failure. Representative captured failures:

1. Exact registered request: `compileTestJava` failed because `AuthorizationRequestValidator` and `AuthorizationRequestCommand` did not exist.
2. Scope membership: `rejectsAnUnregisteredScope()` failed because the first validator accepted `admin:write`.
3. Protected code capability: `compileTestJava` failed because `HmacAuthorizationCodeDigestCapability` did not exist.
4. Transient code issuance: `compileTestJava` failed because the issue service/port/material types did not exist.
5. Atomic persistence: `oneIssuedCodeCanBeConsumedExactlyOnce()` failed on the first V6 consume implementation because the SQL result name was ambiguous.
6. Redemption port: `compileTestJava` failed because the redemption and protected lookup ports did not exist.
7. SAS registration adapter: `compileTestJava` failed because `SasRegisteredClientRepository` did not exist.
8. Clean security scan: the first clean gate failed on two generic `secret` variable assignments; the values were renamed to the semantically accurate `randomValue`, after which the scan passed.

## GREEN and refactor evidence

- Unit tests: **239 passed**, zero failed/skipped.
- PostgreSQL 18/in-process container integration tests: **243 passed**, zero failed/skipped.
- Contract tests: **8 passed**, zero failed/skipped.
- Coverage: **93.93% lines**, **80.54% branches**.
- Clean verification command:
  `./gradlew clean test integrationTest contractTest check contractBundle dependencyPolicyCheck generateSbom secretScan`
- Clean result: **BUILD SUCCESSFUL**, 19/19 tasks executed.
- Contract bundle SHA-256 remained unchanged:
  `fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f`.

The PostgreSQL tests cover sequential replay, barrier-synchronized concurrent redemption, wrong proof without mutation, every NULL redemption/issuance binding, database-clock expiry terminalization, canonical-registration drift rejection at issue and consume, migration-pinned issuer enforcement, runtime direct-table denial, function/table role matrices, literal constraint metadata, V5 upgrade equivalence, prerequisite-role failure, constraint mutations, injected rollback points, protected-at-rest rows, transactional audit facts, full application-context restart replay, and persisted key rotation/removal across full contexts. HTTP/protocol tests cover the exact Dutch redirect, exactly-once query decoding, double-encoded and structural redirect near-misses, encoded path near-miss, duplicate/unknown parameters, duplicate scope tokens, wrong principal shape, decoded-parameter request-size bounds, unauthenticated 401, rate limiting, and continued denial of token/JWKS and unsafe authorization methods.

## Independent-review correction evidence

- **Observed RED — NULL binding:** five direct PostgreSQL invocations with NULL issuer, client, redirect, calculated challenge, or correlation either consumed the code or raised a constraint error. V6 now has explicit NULL guards; all return the same `REJECTED` result and leave the code `ISSUED`. The equivalent issuance bindings raise the bounded issue rejection and leave all three tables empty.
- **Observed RED — duplicate scope:** the corrected one-value HTTP test (`scope=member:read member:read`) initially returned success because set conversion collapsed the duplicate. The SAS converter now rejects duplicates before constructing the framework token.
- Issuance and consumption now re-read `canonical_registration()` and the migration-owned singleton issuer authority. Stored app/client/resource/audience/redirect/scope drift and arbitrary issuers fail closed.
- **Observed RED — full-context restart:** the first real `SpringApplication` restart test exposed an ambiguous production `RegistrationRegistry` injection, then exposed that the test had incorrectly supplied the database owner as the reconciliation authority. Qualified runtime registry injection and distinct least-privilege runtime/reconciler logins made the complete context start, close, rehydrate against the same PostgreSQL database, and reject a consumed code.
- **Observed RED — servlet decoding:** constructing the authorization request from an already percent-escaped mock URI left the encoded spelling as the parameter value and returned `400`. The corrected URI-template endpoint test starts with an unencoded value and succeeds for the canonical redirect while rejecting the double-encoded input. A separate in-process Tomcat test sends literal raw query strings and proves `%3A%2F%2F` becomes the canonical redirect while `%253A%252F%252F` is decoded only to the still-encoded spelling.
- Persisted key rotation uses three full application contexts: V1 writes two database rows; V2-current/V1-readable redeems a V1 code and persists a new V2 code; then V1 removal rejects the remaining persisted V1 code while leaving it `ISSUED`.
- The request bound is a 4096-character default budget over servlet-decoded parameter names and values (not a raw-octet limit). The endpoint uses validated configurable per-client/address windows, bounded to 10,000 live keys, and returns a correlated no-store 429 envelope without echoing the key.
- Direct PostgreSQL matrices enumerate all 17 required issuance arguments and all 9 required consumption arguments. V6 metadata matrices enumerate every non-null authorization column, every authorization FK (including both composite registration bindings), every relevant PK/unique constraint, all audit checks, and immutable audit update/delete behavior.
- Canary injection captures structured application output and Micrometer meter identifiers and proves absence of identity ID, state, nonce, challenge, and raw code. The successful registered `Location` remains the only permitted code occurrence. This service currently configures no tracing exporter or custom trace attributes, so the evidence does not claim an exported-trace capture.
- The implementation decision now explicitly records why W-4 uses the official SAS filter/provider seam directly and intentionally defers `OAuth2AuthorizationService` until W-7 can join code consumption with signed token issuance. This prevents a general pre-consumption `findByToken` seam while `/oauth2/token` remains closed.

## Deliberate stop line and deployment dependencies

- W-4 does not issue access, refresh, or ID tokens and does not open `/oauth2/token`; W-7 must combine redemption with signed token issuance safely.
- No fixture or header-based authentication was added. A real upstream Human Identity authentication journey remains a deployment/product dependency.
- Production-like enablement requires exactly one healthy externally configured authorization-code digest capability with a distinct key reference. Cloud/KMS selection and provisioning remain external deployment work.
- App Subject resolution, activation, DPoP, consent expansion, refresh families, and onboarding events remain later work items.
