# W-7 RED→GREEN evidence

Status: implementation candidate; independent correctness/database and security review required before acceptance.

## Observed behavioral REDs

- The first DPoP proof-verifier test failed compilation because no verifier or typed rejection existed. GREEN added closed ES256/P-256 token and resource proof verification, RFC 7638 thumbprints, exact method/target/time/nonce rules, and `ath`/`cnf.jkt` binding.
- The initial nonce-challenge test failed because the verifier required a nonce before one could be issued. GREEN added a separately closed proof shape that validates every initial-proof property except nonce and never reads an authorization code.
- The token converter/provider tests failed because no official token filter boundary existed. GREEN installs one `OAuth2TokenEndpointFilter` with one closed converter/provider, DPoP-only success, nonce challenge, fixed errors, and no refresh/OIDC path.
- The invalid-proof HTTP test escaped `DpopProofRejectedException`. GREEN maps it to the fixed `invalid_dpop_proof` response without internal detail.
- The first V9 persistence test failed because nonce/replay functions did not exist. GREEN added protected nonce, durable replay, PII-free issuance audit, cleanup, and active security-context authorities.
- A nullable retention test exposed a database constraint error. GREEN rejects it without mutation.
- A cleanup test exposed that the replay immutability trigger also blocked the sanctioned bounded cleanup function. GREEN keeps replay updates forbidden while the definer cleanup remains the only runtime deletion path.
- Orchestration showed that a 43-character nonce cannot convey an internal nonce ID. GREEN consumes by protected digest/key version plus the complete app/client/thumbprint/method/target binding.
- The protected-resource port test failed compilation because no durable replay-authorizing port existed. GREEN verifies the W-6 token and DPoP proof, claims replay durably, and returns only an app-scoped principal.
- The nonce-challenge contract fixture failed because the proof schema required a nonce before the server could issue one. GREEN permits the nonce only as an optional challenge/retry member while semantic rules require it for successful issuance.

## Implemented boundary

- V9 nonce/replay/issuance-audit state and least-authority functions.
- Purpose-separated, versioned external DPoP state digest capability with retained-key reads and production-like fail-closed validation.
- Strict proof validation for token and resource use.
- Atomic challenge replay claim plus nonce issue/supersede.
- One local Spring issuance transaction composing nonce/replay claim, W-4 code redemption, W-5 subject resolution, current identity/security binding, W-6 signing, and issuance audit.
- Official closed `/oauth2/token` filter/provider with bounded inputs, DPoP-only success, nonce retry, standard cache/correlation headers, and excluded protocol paths left closed.
- Durable protected-resource replay port with no public proof-debug endpoint.
- Bounded non-production limiter; production-like profiles require an external limiter bean and external signing/digest capabilities.
- Closed additive language-neutral DPoP header/claim, success, and error contracts with valid/invalid fixtures and semantic requirements.

## Database and privacy evidence

- Runtime has function execution only and no V9 table authority; PUBLIC, relay, reconciler, and unrelated roles are denied.
- Function owners, security-definer flags, volatility, and fixed search paths are asserted.
- Barrier-synchronized resource replay has exactly one winner across connections.
- Nonce supersession, mismatch rejection, duplicate challenge replay, active identity/app-subject binding, bounded cleanup, and transaction rollback after nonce/replay claim are tested on PostgreSQL 18.
- V9 rows contain only protected digests and bounded identifiers; raw proof, JWK, nonce, token, `jti`, `ath`, identity, and App Subject are not persisted in nonce/replay state.
- Commands, results, protected values, and principals redact credential and subject material from diagnostics.

## Clean gate

Command:

`./gradlew clean test integrationTest contractTest check contractBundle dependencyPolicyCheck generateSbom secretScan`

Result: `BUILD SUCCESSFUL`, 19/19 tasks.

- Unit: 310 passed.
- PostgreSQL 18 integration: 279 passed.
- Contract: 8 passed.
- Coverage: 91.23% line, 80.03% branch.
- Checkstyle, dependency policy, SBOM generation, secret scan, migration execution, and contract validation passed.
- Reproducible additive contract digest: `54599dcdb6e492ecc47d0a711d3ee3da79e7a2845935e01adf47524b00cb067a`.

## Intentional external obligations

Production deployment remains fail closed until the cloud workstream supplies the external signer, DPoP digest-key capability, distributed limiter, and trusted public-origin/proxy configuration. Refresh, sessions, OIDC, ID tokens, activation, UMS, and generic DPoP debug endpoints remain excluded.
