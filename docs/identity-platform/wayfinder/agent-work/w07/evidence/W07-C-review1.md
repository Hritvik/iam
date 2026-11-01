# W07-C review 01

Decision: reject

Findings: see evidence/review-01-A-D.md for the full list.
- C-1 medium: single test uses an interrupt-honoring signer; unverified interrupt-ignoring signer, repeated timeouts at workers=1/queue=1, queue saturation, success path, constructor rejection. Evidence mapping overstates coverage.
- C-2 low: caller interruption at future.get does not cancel the task.

Evidence: evidence/review-01-A-D.md
