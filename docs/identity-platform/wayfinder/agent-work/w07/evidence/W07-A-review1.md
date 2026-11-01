# W07-A review 01

Decision: reject

Findings: see evidence/review-01-A-D.md for the full list.
- A-1 medium: maximumAgeSeconds accepted 30–300 vs authority 10–120; skew hardcoded 5 not configurable 0–30; 300 s proof can outlive 120 s replay retention.
- A-2 low: Nimbus accepts padded x/y; thumbprint hashes the padded form, yielding a non-RFC-7638 jkt.
- A-3 low: canonicalization matrix lacks dot segments, non-default port, lowercase percent hex, trailing slash.
- A-4 low: token-endpoint claims schema makes nonce optional and allows six htm values.
- A-5 info: VerifiedDpopProof exposes jti/nonce/thumbprint accessors (redacted in serialization).

Evidence: evidence/review-01-A-D.md
