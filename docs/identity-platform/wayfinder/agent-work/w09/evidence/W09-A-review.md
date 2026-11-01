# W09-A review

Decision: approve

Findings: no critical/high/medium. Relay claims under leases, publishes outside the transaction, acknowledges only after success, redelivers after lease expiry, and quarantines exhausted/non-retryable failures; relay role is least-privilege. Lows: crash-before-ack is proven as failed-publish/lease-expiry here (composed proof is W09-C), no quarantine audit fact, retry cadence equals the lease, thin concurrency/negative-grant tests.
