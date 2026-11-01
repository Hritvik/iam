# W08-B review

Decision: approve

Findings: review 01 found (B-1) forged payload fields accepted, (B-2) non-canonical unverified fingerprint, (B-3) environment unbound, (B-4) divergent duplicate returned EXISTING. All fixed: payload fields are compared to the activation, the factory uses `OnboardingReadyPayload` + `Rfc8785PayloadFingerprint`, the writer recomputes the digest, environment must match the app registration, and divergence is rejected. Remaining lows: SQL does not recompute the digest; duplicate lookup does not include producer/type/environment.
