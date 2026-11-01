# W07-B review 01

Decision: reject

Findings: see evidence/review-01-A-D.md for the full list.
- B-1 medium: partial unique index and supersede predicate compare write-version HMAC digests, so a post-rotation issue cannot see or supersede a pre-rotation live nonce; the supersession test reuses one thumbprint digest and cannot catch it.
- B-2 low: replay protection lapses if an old digest key is removed before replay rows expire; no retention guard or test.
- B-3 low: inverted retention/lifetime fixture; cleanup test counts rows in a shared container without isolation.

Evidence: evidence/review-01-A-D.md
