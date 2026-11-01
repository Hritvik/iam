# W07-E2 review 01

Decision: reject

Findings: MEDIUM W07-E2-1 bean retained the unused DpopStateStore parameter and a constant-true binding verifier (security-looking hook that can never fail). MEDIUM W07-E2-2 evidence overstated "exactly one canonical_registration() per issuance". LOW W07-E2-3 regression test exercised the issuer, not the composed delegate. LOW W07-E2-4 context errors collapse to token_signing_unavailable. LOW W07-E2-5 redundant second resolution.
