# W09-RS evidence — independent security and privacy review

Decision: approve

Findings: no critical/high/medium. The snapshot is app-bound and non-enumerating (mismatch, missing scope, wrong audience, anonymous and malformed input); items are exactly the seven allowlisted fields; the relay publishes only the immutable app-scoped envelope; runtime/relay privileges are separated and V12 is security-definer with a fixed search path. Remaining lows: no production workload authenticator yet (fail-closed 404), standalone MockMvc does not exercise the filter chain, no no-store header, V12 callable by the shared runtime role for any app, no relay destination cross-check, no quarantine audit fact, no rate limiting, reversible cursor, two correlation grammars, pre-existing not-found wording.
