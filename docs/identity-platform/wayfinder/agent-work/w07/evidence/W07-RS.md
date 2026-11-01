# W07-RS evidence — independent security and privacy review

Decision: approve
Findings: no critical/high/medium. 6 low: VerifiedDpopPrincipal Jackson-serializes the App Subject (no reachable sink); local limiter key churn; unhandled DataAccess/Registration exceptions can escape as a container 500; temporarily_unavailable returns 400 without Retry-After; expires_in config-derived; log canary asserts header names not values.

## Verification

- Privacy/HTTP/verifier unit suites 9/9; end-to-end integration 3/3.
- No logger/metric/tracer on the token path; fixed messages; redacted records with @JsonIgnore; closed success and error bodies; no raw proof/nonce/jti/token/subject/identifier persisted.
- Production-like profiles fail closed without external limiter/digest/signer capabilities.
- Signing worker performs no JDBC; deadline bounded; provider detail discarded.
