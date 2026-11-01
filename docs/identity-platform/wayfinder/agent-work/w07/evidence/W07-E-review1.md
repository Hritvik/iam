# W07-E review 01

Decision: reject

Findings: CRITICAL W07-E-1 signing worker re-read human_identity with FOR UPDATE, self-blocking on the request transaction until the signer deadline (every production issuance fails). MEDIUM W07-E-2 evidence claimed code/subject/audit/commit rollback coverage that no test provides. LOW: retention invariant only in configuration; RETRY limiter runs after proof verification; registration re-resolved without requireDpop.
