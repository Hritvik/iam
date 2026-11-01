# Work Unit 02 — Canonical contract catalog and publication

## Scope

This unit owns IAM `contracts/**`, the isolated Gradle `contractTest` source set, and the deterministic local contract bundle. It does not implement runtime IAM behavior or modify Dutch-owned contracts.

## RED

The behavioral tests were written before the contract source existed.

Command:

```text
./gradlew contractTest --write-locks --write-verification-metadata sha256
```

Observed result: `BUILD FAILED`; all five contract tests failed. The failures were the intended missing-boundary failures: `catalog.yaml`, valid/invalid fixture directories, schemas, and the onboarding snapshot OpenAPI document did not exist. The OpenAPI parser returned no model. This established that the tests could not pass against an absent or accepting contract surface.

## GREEN

Implemented:

- a versioned catalog and closed, bounded JSON Schemas for registration, product security policy, authorization metadata, public JWKS, protected-resource metadata, token header/claims, standard HTTP envelopes, shared event envelope, and `iam.app-subject.onboarding-ready.v1`;
- the Dutch development native-public registration with exact `dutch://oauth/callback`, authorization-code only, S256, DPoP, one resource audience, and no client secret or refresh grant;
- an authenticated, app-scoped, cursor/limit-bounded onboarding snapshot OpenAPI contract;
- ten valid conformance fixtures and thirteen explicit invalid fixtures covering global identity ID, raw email/phone, credentials, authorization code, access/refresh tokens, session secret, device fingerprint, cross-app subject, arbitrary payload maps, missing claims, and refresh-grant advertisement;
- mature pinned validators (`json-schema-validator` and Swagger Parser) in an isolated source set, with dependency locks and SHA-256 verification metadata;
- reproducible ZIP and checksum tasks. Generated artifacts remain under `build/` and are not editable contract source.

Command:

```text
./gradlew contractTest contractBundle
```

Observed result: `BUILD SUCCESSFUL`; five test methods passed with zero skipped tests. Each fixture is independently validated in its loop, each negative must fail for its asserted schema reason, and the OpenAPI parser reports no messages.

## Refactor and reproducibility

The contract directory was registered as an explicit `contractTest` input after a changed fixture initially revealed that Gradle could otherwise report the test task up-to-date. The test then correctly reran and exposed a negative-reason assertion, which was tightened before returning to GREEN.

Two unchanged builds produced byte-identical archives:

```text
first=21d8e5859ae1fd9a1f058664a868c1117dfc4802549a2a1b2e5c270c0097cb2c
second=21d8e5859ae1fd9a1f058664a868c1117dfc4802549a2a1b2e5c270c0097cb2c
iam-contracts-1.0.0.zip: OK
```

The verification used `sha256sum -c build/distributions/iam-contracts-1.0.0.sha256` from the distribution directory after `./gradlew clean contractBundle`.

## Foundation regression gate

Command:

```text
./gradlew test integrationTest check contractBundle
```

Observed result after the only Checkstyle issue (an unused test import) was removed: `BUILD SUCCESSFUL`. Unit tests, PostgreSQL integration tests, contract tests, Checkstyle, dependency policy, SBOM generation, JaCoCo thresholds, and the secret scan passed. No test was disabled or silently skipped.

No commit, push, remote publication, Dutch change, production Java behavior, or migration change was made.

## Review correction cycle

Independent review rejected the first GREEN because validator routing metadata had leaked into protocol instances, the generic success body admitted arbitrary nested data, the event envelope was not reusable, and semantic app-binding/token/event relationships were not executable. Acceptance therefore reopened under a new RED/GREEN cycle; the earlier digest above is historical and superseded.

### Correction RED

Tests were first expanded to require external `{schema, instance}` fixture mapping, an exact non-vacuous inventory, recursive privacy checks, fully parsed unique catalog entries, reusable event structure plus semantic cross-field equality, registered-workload snapshot binding, format assertions, and Dutch-specific token conformance.

```text
./gradlew contractTest
```

Observed result: `BUILD FAILED`; seven tests executed and six failed. The failures proved the old artifacts lacked external schema routing, payload/example catalog entries, mTLS app binding, semantic event checks, and semantic token validation.

### Correction GREEN

- Removed `$contract` from every runtime JSON schema and wire instance. Fixture schema selection is now external.
- Closed the only current success data shape to the onboarding snapshot; successful bodies do not require a correlation field. Error correlation remains in the error body, and optional details allow only `field`, `code`, and safe `message`.
- Added 34 explicit negatives, including every forbidden field nested inside otherwise valid response data, arbitrary nested data, three onboarding cross-field mismatches, six Dutch token mismatches, insecure/malformed URIs, malformed date-time, refresh advertisement, and a runtime `$contract` marker.
- Made the shared event envelope structural and bounded. The onboarding event narrows it, uses `FIRST_ACTIVATION`, and permits `RECONCILIATION` only for snapshot-derived repair. Semantic validation binds destination/payload app, aggregate/payload activation, and aggregate/onboarding versions.
- Replaced the conflicting client-credentials discovery implication with registered-workload mTLS. The snapshot operation pins app binding, internal audience, scope, non-enumerating 404, cursor/limit bounds, and closed canonical item fields.
- Enabled JSON Schema format assertions and HTTPS requirements. Token conformance is checked against the canonical Dutch manifest and OAuth metadata for issuer, app, client, audience, scope, and DPoP.
- Catalog validation now enforces unique names/paths, exact schema versions, full parsing/resolution, and direct validation of the canonical Dutch example. The payload component is cataloged. Gradle derives the bundle semantic version from the catalog.
- The catalog explicitly describes OAuth Authorization Server metadata only; this unit does not claim OIDC discovery or define ID tokens.

```text
./gradlew contractTest checkstyleContractTest contractBundle
```

Observed result: `BUILD SUCCESSFUL`; seven contract tests passed with zero skipped tests against ten valid and 34 invalid fixtures.

Two clean builds produced byte-identical corrected archives:

```text
first=44e43e6d50e2617a1a48bd15e948f48d85433de99571e95206c48328591854c0
second=44e43e6d50e2617a1a48bd15e948f48d85433de99571e95206c48328591854c0
iam-contracts-1.0.0.zip: OK
```

Final regression command:

```text
./gradlew test integrationTest check contractBundle
```

Observed result: `BUILD SUCCESSFUL` with the unit, PostgreSQL integration, seven contract tests, Checkstyle, dependency policy, SBOM, JaCoCo, and secret scan gates passing. `sha256sum -c` also reported `iam-contracts-1.0.0.zip: OK`. Git diff checking remains unavailable because this IAM directory has no `.git` metadata.

## Final review cleanup cycle

The final review requested endpoint-specific success naming, canonical/OpenAPI error parity, retryable response metadata, token time semantics, and an exact catalog inventory. The subsequent security review also required leak-proof public errors, safe redirect URI classes, and published semantic MUST requirements.

### Cleanup RED

Tests were changed first to require the exact 15-file publishable inventory, `onboarding-snapshot-response.schema.json`, an expanded invalid-fixture inventory, 429/500/503 responses, `Retry-After`, closed OpenAPI details, and the semantic requirements artifact.

```text
./gradlew contractTest
```

Observed result: `BUILD FAILED`; seven tests executed and three failed. The failures identified the old generic success name/inventory, missing resilience responses and error details parity, and the absent expanded fixture inventory.

### Cleanup GREEN

- Renamed the closed response contract to `onboarding-snapshot-response.schema.json`; there is no misleading generic success-data contract.
- Aligned canonical and OpenAPI error contracts. Public code/message pairs are stable and allowlisted. Optional details contain only allowlisted `field` and `code` values—never arbitrary messages.
- Added raw email, phone, and token error-message negatives.
- Added 429, 500, and 503 responses; 429 and 503 reference a retryable response with bounded required `Retry-After`.
- Added semantic `exp > iat` and conditional `auth_time <= iat` validation plus explicit negative fixtures.
- Restricted native redirects to HTTPS, RFC 8252 loopback-IP HTTP, or non-web custom schemes; `javascript`, `data`, and `file` fixtures are rejected.
- Published language-neutral MUST requirements for app-owned custom schemes/claimed HTTPS, onboarding cross-field equality, token-registration tuple/time/DPoP semantics, and mandatory enforcement of the OpenAPI audience/scope/app-binding extensions.
- Catalog tests now compare against the exact authored publishable inventory rather than only proving that listed paths exist.

```text
./gradlew contractTest checkstyleContractTest contractBundle
```

Observed result: `BUILD SUCCESSFUL`; all seven contract tests passed against ten valid and 44 invalid fixtures, including mismatched public code/message and non-loopback HTTP redirect cases.

Two unchanged clean builds were byte-identical and the generated checksum verified:

```text
first=4c9044a3a825d1855497a121d645c784aa8126fbe7c997031b2b3ff2e6056021
second=4c9044a3a825d1855497a121d645c784aa8126fbe7c997031b2b3ff2e6056021
iam-contracts-1.0.0.zip: OK
```

## RFC 8252 loopback and resource-audience correction

The final security review identified that the schema-level loopback regex did not prove valid IP octets or port bounds and could admit 127-like hostnames. A semantic URI parser was selected because encoding these rules only in regex would be difficult to audit and maintain.

### RED

The contract test was changed first to require 53 invalid fixtures and to accept three known-good explicit-port loopbacks: IPv4 `127.0.0.1`, another address inside `127/8`, and IPv6 exactly `[::1]`. Semantic validation was deliberately absent.

```text
./gradlew contractTest
```

Observed result: `BUILD FAILED`; eight tests executed and two failed—the new fixture inventory was absent and all known-good loopbacks failed the placeholder semantic validator.

### GREEN

- Added language-neutral normative rules requiring an exact four-octet IPv4 address inside `127/8` with every octet in `0..255`, or IPv6 exactly `[::1]`.
- Required an explicit numeric HTTP loopback port in `1..65535`.
- Semantically rejected malformed 127-like hosts, invalid octets, port zero, ports above 65535, non-loopback IPv6, userinfo, and fragments.
- Retained schema-level rejection for unsafe schemes and added dedicated negative fixtures for every loopback attack class.
- Required app-registration resource audiences to use HTTPS and added an insecure-manifest-audience negative fixture.

```text
./gradlew contractTest checkstyleContractTest contractBundle
```

Observed result: `BUILD SUCCESSFUL`; eight contract tests passed against ten valid and 53 invalid fixtures.

Two unchanged clean builds were byte-identical and the checksum verified:

```text
first=fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f
second=fadba94390448f36cb0def04be812683841b8887e64e3d5e049b9d359146ff6f
iam-contracts-1.0.0.zip: OK
```
