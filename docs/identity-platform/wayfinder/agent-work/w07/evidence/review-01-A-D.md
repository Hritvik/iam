# Independent review 01 — W07-A through W07-D

- Reviewer: `REVIEWER-01` (independent subagent; did not write the code)
- Date: 2026-10-30
- Threshold: medium (board `review_threshold`)
- Gates run: focused unit 27/27, DpopPersistenceIntegrationTest 15/15 (forced rerun), contractTest 8/8

## Verdicts

| Packet | Verdict | Highest severity |
|---|---|---|
| W07-A | REJECT (reopen) | medium |
| W07-B | REJECT (reopen) | medium |
| W07-C | REJECT (reopen) | medium |
| W07-D | REJECT (reopen) | high |

## W07-A findings

- **A-1 (medium)** `DpopProofVerifier` accepts `maximumAgeSeconds` 30–300; the decisions authority fixes 10–120. Future skew is hardcoded to 5 s instead of configurable 0–30 s. A 300 s proof can outlive its 120 s replay row.
- **A-2 (low, empirically shown)** Nimbus accepts padded `x`/`y` JWK coordinates and `computeThumbprint()` hashes the padded form, so a non-canonical JWK yields a non-RFC-7638 `jkt`. No signature bypass, but it contradicts the closed contract.
- **A-3 (low)** Canonicalization test matrix lacks `..`, non-default ports, lowercase percent hex, trailing slash.
- **A-4 (low)** `dpop-proof-claims.schema.json` makes `nonce` optional and allows six `htm` values although the token-endpoint schema requires exactly `jti,htm,htu,iat,nonce` with `htm=POST`.
- **A-5 (info)** `VerifiedDpopProof` exposes `jti()/nonce()/keyThumbprint()`; redacted in serialization, needed by W07-E.

## W07-B findings

- **B-1 (medium)** One-live-binding supersession breaks across digest-key rotation: the partial unique index and supersede predicate compare write-version HMAC digests, so a post-rotation issue cannot see or supersede the pre-rotation live nonce. The existing supersession test reuses one thumbprint digest and cannot catch it.
- **B-2 (low)** Replay protection silently lapses if an old digest key is removed before replay rows expire; no key-retention guard or test.
- **B-3 (low)** Test fixture passes inverted retention/lifetime arguments; cleanup test counts rows in a shared container without per-test isolation.

## W07-C findings

- **C-1 (medium)** The only test uses an interrupt-honoring signer. Unverified: interrupt-ignoring signer, repeated timeouts against `workers=1,queue=1`, queue saturation, success path, constructor rejection. Evidence overstates the mapping.
- **C-2 (low)** Caller interruption at `future.get` does not cancel the task, so a worker stays occupied after the request failed.

## W07-D findings

- **D-1 (high)** The emitted OAuth error body violates `contracts/oauth/token-error-response.schema.json`: no `correlation_id` in the body, a generic `error_description` matching no per-code value, and `unsupported_grant_type` outside the closed `error` enum (converter emits it for e.g. `grant_type=refresh_token`). `contractTest` validates fixtures only, so it is green while the wire shape is wrong; the HTTP test asserts the non-conforming description.
- **D-2 (medium)** HTTP correlation validation accepts `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, then prefixes `cor_` for persistence which requires `^cor_[A-Za-z0-9_-]{16,128}$`. Short or dotted values hit the V9 CHECK and become `temporarily_unavailable`, turning a normal challenge into a 500.
- **D-3 (low)** Privacy test does not cover `DpopTokenRequestAuthenticationToken` or `DpopNonceRequiredException`.
- **D-4 (low)** LRU eviction lets an attacker reset an exhausted local bucket by key churn (production requires the external limiter).
- **D-5 (low)** `invalid_client` never emitted; all failures are 400 including `temporarily_unavailable`; chunked bodies bypass the raw-size precheck.

## Conclusion

No critical findings. D-1 is high; A-1, B-1, C-1, D-2 are medium. All four packets are reopened.

## Remediation status (2026-10-30)

Fixes applied and verified green after the review:

- **D-1 (high) fixed**: failure handler now emits `error`, the per-code fixed `error_description`, and `correlation_id` in the body; `unsupported_grant_type` removed from the closed set (unsupported grants map to `invalid_request`); HTTP test asserts the contract value and body correlation.
- **D-2 (medium) fixed**: both DPoP correlation producers validate the final value against `^cor_[A-Za-z0-9_-]{16,128}$` and generate a fresh ID otherwise, so V9 CHECK constraints can no longer convert a challenge into a 500.
- **A-1 (medium) fixed**: proof maximum age bounds tightened to 10–120 s; future skew is now a constructor parameter bounded 0–30 s (default 5 s) and wired via `iam.dpop.proof-maximum-future-skew-seconds`; tests updated (9/121 rejected, skew 31 rejected).
- **A-2 (low) fixed**: `canonicalCoordinate` rejects any `x`/`y` that is not exactly 43 unpadded base64url characters round-tripping to 32 bytes.
- **C-1 (medium) fixed**: `DeadlineTokenAccessIssuerTest` now covers the success path, constructor bounds, and an interrupt-ignoring signer at `workers=1, queue=1` proving submissions beyond worker+queue are rejected (4 tests).

Gates after remediation: focused unit suites 26 tests, `DpopPersistenceIntegrationTest` 15, `contractTest` 8 — all green.

Still open:

- **B-1 (medium)**: one-live-binding supersession across digest-key rotation. Requires carrying readable alias sets for thumbprint/target into `issue_dpop_nonce` (or a stable binding digest) so the supersede predicate and live-binding rule span key versions. Not yet implemented.
- A-3/A-4 (low), B-2/B-3 (low), D-3/D-4/D-5 (low): test/contract polish.

The four packets therefore remain `ready` (reopened), not green, pending B-1 and a second review.
