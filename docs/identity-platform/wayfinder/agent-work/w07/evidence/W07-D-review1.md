# W07-D review 01

Decision: reject

Findings: see evidence/review-01-A-D.md for the full list.
- D-1 high: error body lacks correlation_id, uses an error_description matching no per-code value, and emits unsupported_grant_type outside the closed enum; contractTest validates fixtures only and the HTTP test asserts the non-conforming description.
- D-2 medium: HTTP correlation validation permits values the V9 CHECK rejects, turning a nonce challenge into temporarily_unavailable.
- D-3 low: privacy test omits DpopTokenRequestAuthenticationToken and DpopNonceRequiredException.
- D-4 low: LRU eviction lets key churn reset an exhausted local bucket.
- D-5 low: invalid_client never emitted; all errors are 400; chunked bodies bypass the raw-size precheck.

Evidence: evidence/review-01-A-D.md
