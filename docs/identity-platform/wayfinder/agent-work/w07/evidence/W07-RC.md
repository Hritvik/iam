# W07-RC evidence — independent correctness and database review

Decision: approve
Findings: no critical/high/medium. 8 low: MockMvc rather than socket and no end-to-end JWT/cnf assertions; expires_in config-derived; challenge replay mapped to invalid_grant; cleanup function has no caller/index; no trigger/constraint matrix tests; disabled identity returns 503; challenge/consume lock-order inversion under same-jti reuse; board revision drift.

## Verification

- `DpopTokenEndpointIntegrationTest` 3/3 and `DpopPersistenceIntegrationTest` 16/16 against PostgreSQL 18.
- `contractTest` 8/8.
- End-to-end test uses the real store, redemption, resolver, issuer and deadline adapter; only the three permitted external ports are test beans.
- V9: alias supersession, advisory-lock scope, NULL handling, ACL/least privilege, bounded cleanup and terminal-state trigger all correct.
- Transaction and lock order: identity before app subject in both paths; no inversion; rollback complete.
