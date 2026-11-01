# W07-E review 02

Decision: reject

Findings: HIGH W07-E-R2-1 the signer worker still performs `canonical_registration()` through JdbcRegistrationRegistry, so each in-flight issuance needs a second pooled connection while the request transaction holds one; under ~8 concurrent exchanges the pool is exhausted and every request fails with token_signing_unavailable. MEDIUM W07-E-R2-2 the binding verifier is now a constant true (compensated only by the orchestrator's authority read). MEDIUM W07-E-R2-3 board/evidence overclaim that the worker no longer touches the DB, and the rollback-seam acceptance line is unproven. LOW unused DpopStateStore parameter; double registration resolution per exchange.
