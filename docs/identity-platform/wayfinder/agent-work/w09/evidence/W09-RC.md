# W09-RC evidence — independent correctness and database review

Decision: approve

Findings: review 01 rejected the missing HTTP binding (H-1), unmapped database failures (M-1), missing ack/quarantine fencing tests (M-2), and a non-integer limit returning 500 (M-3). All fixed: the controller is a mapped `@RestController` at the contracted route with a dedicated security chain and standalone-MockMvc tests for 200/404/400/500; unexpected failures return the internal_error envelope; stale/foreign acknowledgements and quarantines are rejected; limit is parsed and invalid text returns 400. Remaining lows: relay scheduling and production transport are deployment wiring, no quarantine audit fact, implicit state fencing, cursor pinned to the 24-char subject, absent-but-bound app returns an empty page.
